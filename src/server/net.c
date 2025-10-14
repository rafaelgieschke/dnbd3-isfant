/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "helper.h"
#include "image.h"
#include "uplink.h"
#include "locks.h"
#include "rpc.h"
#include "altservers.h"
#include "reference.h"

#include "spdk/iscsi_spec.h"
#include "spdk/scsi_spec.h"
#include <endian.h>

#include <dnbd3/shared/sockhelper.h>
#include <dnbd3/shared/timing.h>
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/serialize.h>

#include <assert.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include <jansson.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <signal.h>

static dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
static int _num_clients = 0;
static pthread_mutex_t _clients_lock;

static char nullbytes[500];

static atomic_uint_fast64_t totalBytesSent = 0;

// Adding and removing clients -- list management
static bool addToList(dnbd3_client_t *client);
static void removeFromList(dnbd3_client_t *client);
static dnbd3_client_t* freeClientStruct(dnbd3_client_t *client);
static void uplinkCallback(void *data, uint64_t handle, uint64_t start, uint32_t length, const char *buffer);

static inline bool recv_request_header_raw(dnbd3_client_t *client, void *request, size_t size)
{
	int sock = client->sock;
	ssize_t ret, fails = 0;
#ifdef DNBD3_SERVER_AFL
	sock = 0;
#endif
	// Read request header from socket
	while ( ( ret = recv( sock, request, size, MSG_WAITALL ) ) != size ) {
		if ( errno == EINTR && ++fails < 10 ) continue;
		if ( ret >= 0 || ++fails > SOCKET_TIMEOUT_CLIENT_RETRIES ) return false;
		if ( errno == EAGAIN ) continue;
		logadd( LOG_DEBUG2, "Error receiving request: Could not read message header (%d/%d, e=%d)\n", (int)ret, (int)size, errno );
		return false;
	}
	return true;
}

static inline bool translate_iscsi_to_dndb3( dnbd3_client_t *client, struct iscsi_bhs *bhs, dnbd3_request_t *request );

static inline bool recv_request_header( dnbd3_client_t *client, dnbd3_request_t *request )
{
	if ( client->iscsi ) {
		struct iscsi_bhs bhs;
		if ( !recv_request_header_raw( client, &bhs, sizeof bhs ) ) return false;
		if ( !translate_iscsi_to_dndb3( client, &bhs, request ) ) return false;
	} else {
		if ( !recv_request_header_raw( client, request, sizeof *request ) ) return false;
		// Make sure all bytes are in the right order (endianness)
		fixup_request( *request );
	}
	if ( request->magic != dnbd3_packet_magic ) {
		logadd( LOG_DEBUG2, "Magic in client request incorrect (cmd: %d, len: %d)\n", (int)request->cmd, (int)request->size );
		return false;
	}
	// Payload sanity check
	if ( request->cmd != CMD_GET_BLOCK && request->size > MAX_PAYLOAD ) {
		logadd( LOG_WARNING, "Client tries to send a packet of type %d with %d bytes payload. Dropping client.", (int)request->cmd, (int)request->size );
		return false;
	}
	return true;
}

static inline bool recv_request_payload(int sock, uint32_t size, serialized_buffer_t *payload)
{
#ifdef DNBD3_SERVER_AFL
	sock = 0;
#endif
	if ( size == 0 ) {
		logadd( LOG_ERROR, "Called recv_request_payload() to receive 0 bytes" );
		return false;
	}
	if ( size > MAX_PAYLOAD ) {
		logadd( LOG_ERROR, "Called recv_request_payload() for more bytes than the passed buffer could hold!" );
		return false;
	}
	if ( sock_recv( sock, payload->buffer, size ) != (ssize_t)size ) {
		logadd( LOG_DEBUG1, "Could not receive request payload of length %d\n", (int)size );
		return false;
	}
	// Prepare payload buffer for reading
	serializer_reset_read( payload, size );
	return true;
}

static inline bool send_reply_raw(int sock, const void *reply, size_t reply_size, const void *payload, size_t size )
{
	if ( sock_sendAll( sock, reply, reply_size, 1 ) != reply_size ) {
		logadd( LOG_DEBUG1, "Sending reply header to client failed" );
		return false;
	}
	if ( size != 0 && payload != NULL ) {
		if ( sock_sendAll( sock, payload, size, 1 ) != (ssize_t)size ) {
			logadd( LOG_DEBUG1, "Sending payload of %"PRIu32" bytes to client failed", size );
			return false;
		}
	}
	return true;
}

static inline bool sendPadding( const int fd, uint32_t bytes );

static inline bool send_reply_iscsi( dnbd3_client_t *client, struct iscsi_bhs *reply, const void *payload, size_t size )
{
	reply->data_segment_len[0] = size >> 16;
	reply->data_segment_len[1] = size >> 8;
	reply->data_segment_len[2] = size >> 0;
	((struct iscsi_bhs_scsi_resp *)reply)->exp_cmd_sn = htobe32( client->exp_cmd_sn );
	((struct iscsi_bhs_scsi_resp *)reply)->max_cmd_sn = htobe32( client->exp_cmd_sn + 0x100 );
	if ( !send_reply_raw( client->sock, reply, sizeof *reply, payload, size ) ) {
		return false;
	}
	return sendPadding( client->sock, ISCSI_ALIGN( size ) - size );
}

static inline bool send_reply_iscsi_lock( dnbd3_client_t *client, struct iscsi_bhs *reply, const void *payload, size_t size )
{
	mutex_lock( &client->sendMutex );
	bool ret = send_reply_iscsi( client, reply, payload, size );
	mutex_unlock( &client->sendMutex );
	return ret;
}

/**
 * Send reply with optional payload. payload can be null. The caller has to
 * acquire the sendMutex first.
 */
static inline bool send_reply( dnbd3_client_t *client, dnbd3_reply_t *reply, const void *payload )
{
	const uint32_t size = reply->size;
	if ( client->iscsi ) {
		struct iscsi_bhs bhs = { 0 };
		bhs.itt = reply->handle;
		switch (reply->cmd) {
			case CMD_SELECT_IMAGE:
				bhs.opcode = ISCSI_OP_LOGIN_RSP;
				bhs.flags = ISCSI_LOGIN_TRANSIT | ISCSI_LOGIN_CURRENT_STAGE_0 | ISCSI_LOGIN_NEXT_STAGE_3;
				break;
			case CMD_GET_BLOCK:
				bhs.opcode = ISCSI_OP_SCSI_DATAIN;
				bhs.flags = ISCSI_FLAG_FINAL | ISCSI_DATAIN_STATUS;
				break;
			case CMD_KEEPALIVE:
				return true;
			default: {
				bhs.opcode = ISCSI_OP_SCSI_RSP;
				bhs.flags = ISCSI_FLAG_FINAL;
				((struct iscsi_bhs_scsi_resp *)&bhs)->status = SPDK_SCSI_STATUS_CHECK_CONDITION;
				uint8_t data[20] = { (sizeof data - 2) >> 8, sizeof data - 2, 0x70, 0, SPDK_SCSI_SENSE_ILLEGAL_REQUEST, 0, 0, 0, 0, sizeof data - 2 - 8, 0, 0, 0, 0, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE };
				return send_reply_iscsi_lock( client, (struct iscsi_bhs *)&bhs, &data, sizeof data );
			}
		}
		return send_reply_iscsi( client, &bhs, payload, size );
	}
	fixup_reply( *reply );
	return send_reply_raw( client->sock, reply, sizeof(*reply), payload, size );
}

/**
 * Send given amount of null bytes. The caller has to acquire the sendMutex first.
 */
static inline bool sendPadding( const int fd, uint32_t bytes )
{
	ssize_t ret;
	while ( bytes >= sizeof(nullbytes) ) {
		ret = sock_sendAll( fd, nullbytes, sizeof(nullbytes), 2 );
		if ( ret <= 0 )
			return false;
		bytes -= (uint32_t)ret;
	}
	return sock_sendAll( fd, nullbytes, bytes, 2 ) == (ssize_t)bytes;
}

void net_init()
{
	mutex_init( &_clients_lock, LOCK_CLIENT_LIST );
}

static inline bool translate_iscsi_to_dndb3( dnbd3_client_t *client, struct iscsi_bhs *bhs, dnbd3_request_t *request )
{
	client->exp_cmd_sn = be32toh( ((struct iscsi_bhs_scsi_req*)bhs)->cmd_sn ) + ( bhs->immediate ? 0 : 1 );
	request->magic = dnbd3_packet_magic;
	request->cmd = CMD_KEEPALIVE;
	request->size = ISCSI_ALIGN( bhs->data_segment_len[0] << 16 | bhs->data_segment_len[1] << 8 | bhs->data_segment_len[2] );
	if ( bhs->opcode != ISCSI_OP_LOGIN && request->size != 0 ) return false;
	if ( bhs->total_ahs_len != 0 ) return false;
	request->handle = bhs->itt;

	struct iscsi_bhs resp = { 0 };
	resp.itt = bhs->itt;
	resp.flags = ISCSI_FLAG_FINAL;
	switch ( bhs->opcode ) {
		case ISCSI_OP_LOGIN:
			request->cmd = CMD_SELECT_IMAGE;
			return true;
		case ISCSI_OP_LOGOUT:
			resp.opcode = ISCSI_OP_LOGOUT_RSP;
			send_reply_iscsi_lock( client, &resp, NULL, 0 );
			return false;
		case ISCSI_OP_NOPOUT:
			resp.opcode = ISCSI_OP_NOPIN;
			resp.ttt = 0xffffffff;
			return send_reply_iscsi_lock( client, &resp, NULL, 0 );
		case ISCSI_OP_TASK:
			resp.opcode = ISCSI_OP_TASK_RSP;
			return send_reply_iscsi_lock( client, &resp, NULL, 0 );
		case ISCSI_OP_SCSI: {
			struct iscsi_bhs_scsi_req *req = (struct iscsi_bhs_scsi_req *)bhs;
			uint32_t expected_data_xfer_len = be32toh( req->expected_data_xfer_len );
			resp.opcode = ISCSI_OP_SCSI_RSP;
			if ( expected_data_xfer_len > 0 ) {
				resp.opcode = ISCSI_OP_SCSI_DATAIN;
				resp.flags |= ISCSI_DATAIN_STATUS;
			}
			switch ( req->cdb[0] ) {
				case SPDK_SPC_TEST_UNIT_READY:
					return send_reply_iscsi_lock( client, &resp, NULL, 0 );
				case SPDK_SPC_REPORT_LUNS: {
					uint8_t data[] = { 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
					return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
				}
				case SPDK_SPC_INQUIRY: {
					struct spdk_scsi_cdb_inquiry *inquiry = (struct spdk_scsi_cdb_inquiry *)&req->cdb;
					switch ( inquiry->evpd & 0x01 ) {
						case 0: {
							struct spdk_scsi_cdb_inquiry_data data = { .peripheral_device_type = 0, .version = 4, .response = 2, .add_len = sizeof data - 4, .t10_vendor_id = "IET     ", .product_id = "VIRTUAL-DISK    ", .product_rev = "0001" };
							return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
						}
						case 1: {
							switch ( inquiry->page_code ) {
								case 0x00: {
									uint8_t data[6] = { 0x0, inquiry->page_code, (sizeof data - 4) >> 8, sizeof data - 4, 0x00, 0xb0 };
									return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
								}
								case 0xb0: {
									uint8_t data[64] = { 0x0, inquiry->page_code, (sizeof data - 4) >> 8, sizeof data - 4, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0 };
									return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
								}
							}
						}
					}
				}
				case SPDK_SPC_MODE_SENSE_6: {
					uint8_t data[24] = { sizeof data - 4, 0, 0b10000000, 0, 0x8, 0x12, 0x14, 0x0, 0xff, 0xff, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
					return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
				}
				case SPDK_SBC_READ_CAPACITY_10: {
					uint32_t size = client->image ? ( client->image->virtualFilesize / 512 - 1 ) : 0;
					uint8_t data[8] = { size >> 24, size >> 16, size >> 8, size, 0, 0, 2, 0 };
					return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
				}
				case SPDK_SPC_SERVICE_ACTION_IN_16:
					switch ( req->cdb[1] & 0x1f ) {
						case SPDK_SBC_SAI_READ_CAPACITY_16: {
							uint64_t size = client->image ? ( client->image->virtualFilesize / 512 - 1 ) : 0;
							uint8_t data[32] = { size >> 56, size >> 48, size >> 40, size >> 32, size >> 24, size >> 16, size >> 8, size, 0, 0, 2, 0 };
							return send_reply_iscsi_lock( client, &resp, &data, MIN( sizeof data, expected_data_xfer_len ) );
						}
					}
					break;
				case SPDK_SBC_READ_10:
					request->cmd = CMD_GET_BLOCK;
					request->size = ( req->cdb[7] << 8 | req->cdb[8] ) * 512;
					request->offset = ( (uint64_t)req->cdb[2] << 24 | (uint64_t)req->cdb[3] << 16 | (uint64_t)req->cdb[4] << 8 | (uint64_t)req->cdb[5] ) * 512;
					return true;
				case SPDK_SBC_READ_16:
					request->cmd = CMD_GET_BLOCK;
					request->size = ( req->cdb[10] << 24 | req->cdb[11] << 16 | req->cdb[12] << 8 | req->cdb[13] ) * 512;
					request->offset = ( (uint64_t)req->cdb[2] << 56 | (uint64_t)req->cdb[3] << 48 | (uint64_t)req->cdb[4] << 40 | (uint64_t)req->cdb[5] << 32 | (uint64_t)req->cdb[6] << 24 | (uint64_t)req->cdb[7] << 16 | (uint64_t)req->cdb[8] << 8 | (uint64_t)req->cdb[9] ) * 512;
					return true;
			}
			logadd( LOG_WARNING, "Unsupported SCSI command 0x%02x 0x%02x received from iSCSI client %s", req->cdb[0], req->cdb[1], client->hostName );
			resp.opcode = ISCSI_OP_SCSI_RSP;
			resp.flags = ISCSI_FLAG_FINAL;
			((struct iscsi_bhs_scsi_resp *)&resp)->status = SPDK_SCSI_STATUS_CHECK_CONDITION;
			uint8_t data[20] = { (sizeof data - 2) >> 8, sizeof data - 2, 0x70, 0, SPDK_SCSI_SENSE_ILLEGAL_REQUEST, 0, 0, 0, 0, sizeof data - 2 - 8, 0, 0, 0, 0, SPDK_SCSI_ASC_NO_ADDITIONAL_SENSE, SPDK_SCSI_ASCQ_CAUSE_NOT_REPORTABLE };
			return send_reply_iscsi_lock( client, &resp, &data, sizeof data );
		}
    }
	logadd( LOG_WARNING, "Unsupported iSCSI command 0x%02x received from iSCSI client %s", bhs->opcode, client->hostName );
	return send_reply_iscsi_lock( client, (struct iscsi_bhs *)&(struct iscsi_bhs_reject){ .opcode = ISCSI_OP_REJECT, .flags = ISCSI_FLAG_FINAL, .reason = ISCSI_REASON_CMD_NOT_SUPPORTED, .ffffffff = 0xffffffff }, bhs, sizeof *bhs );
}

void* net_handleNewConnection(void *clientPtr)
{
	dnbd3_client_t * const client = (dnbd3_client_t *)clientPtr;
	dnbd3_request_t request;
	client->thread = pthread_self();

	// Await data from client. Since this is a fresh connection, we expect data right away
	sock_setTimeout( client->sock, _clientTimeout );
	setsockopt( client->sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof (int) );
	do {
#ifdef DNBD3_SERVER_AFL
		const int ret = (int)recv( 0, &request, sizeof(request), MSG_WAITALL );
#else
		const int ret = (int)recv( client->sock, &request, sizeof(request), MSG_WAITALL );
#endif
		// It's expected to be a real dnbd3 client
		// Check request for validity. This implicitly dictates that all HTTP requests are more than 24 bytes...
		if ( ret != (int)sizeof(request) ) {
			logadd( LOG_DEBUG2, "Error receiving request: Could not read message header (%d/%d, e=%d)", (int)ret, (int)sizeof(request), errno );
			goto fail_preadd;
		}

		if ( ((char*)&request)[0] == 'C' ) {
			client->iscsi = 1;
			struct iscsi_bhs bhs;
			memcpy( &bhs, &request, sizeof request );
			const int ret = (int)recv( client->sock, (char*)&bhs + sizeof request, sizeof bhs - sizeof request, MSG_WAITALL );
			if ( ret != (int)( sizeof bhs - sizeof request ) ) {
				logadd( LOG_DEBUG2, "Error receiving request: Could not read iSCSI extra message header (%d/%d, e=%d)", (int)ret, (int)( sizeof bhs - sizeof request ), errno );
				goto fail_preadd;
			}
			translate_iscsi_to_dndb3( client, &bhs, &request );
		}
		if ( request.magic != dnbd3_packet_magic ) {
			// Let's see if this looks like an HTTP request
			if ( ((char*)&request)[0] == 'G' || ((char*)&request)[0] == 'P' ) {
				// Close enough...
				rpc_sendStatsJson( client->sock, &client->host, &request, ret );
			} else {
				logadd( LOG_DEBUG1, "Magic in client handshake incorrect" );
			}
			goto fail_preadd;
		}
		// Magic OK, untangle byte order if required
		if ( !client->iscsi ) fixup_request( request );
		if ( request.cmd != CMD_SELECT_IMAGE ) {
			logadd( LOG_WARNING, "Client sent != CMD_SELECT_IMAGE in handshake (got cmd=%d, size=%d), dropping client.", (int)request.cmd, (int)request.size );
			goto fail_preadd;
		}
	} while (0);
	// Fully init client struct
	mutex_init( &client->lock, LOCK_CLIENT );
	mutex_init( &client->sendMutex, LOCK_CLIENT_SEND );

	mutex_lock( &client->lock );
	host_to_string( &client->host, client->hostName, HOSTNAMELEN );
	client->hostName[HOSTNAMELEN-1] = '\0';
	mutex_unlock( &client->lock );
	client->bytesSent = 0;
	client->relayedCount = 0;

	if ( !addToList( client ) ) {
		freeClientStruct( client );
		logadd( LOG_WARNING, "Could not add new client to list when connecting" );
		return NULL;
	}

	dnbd3_reply_t reply;

	dnbd3_image_t *image = NULL;
	dnbd3_cache_map_t *cache = NULL;
	int image_file = -1;

	int num;
	bool bOk = false;
	bool hasName = false;

	serialized_buffer_t payload;
	uint16_t rid, client_version;

	dnbd3_server_entry_t server_list[NUMBER_SERVERS];

	// Set to zero to make valgrind happy
	memset( &reply, 0, sizeof(reply) );
	memset( &payload, 0, sizeof(payload) );
	reply.magic = dnbd3_packet_magic;

	// Receive first packet's payload
	if ( recv_request_payload( client->sock, request.size, &payload ) ) {
		char *image_name;
		uint8_t flags;
		if ( client->iscsi ) {
			client_version = MIN_SUPPORTED_CLIENT;
			rid = 1;
			flags = 0;
			for (char *keyValue; ( keyValue = serializer_get_string( &payload ) ) != NULL; ) {
				if (strncmp(keyValue, "TargetName=", strlen( "TargetName=" ) ) == 0) {
					image_name = keyValue + strlen ( "TargetName=" );
					for ( char *c = image_name; *c; c++ ) if ( *c == ':' ) *c = '/';
					char *dot = strrchr( image_name, '.' );
					if ( dot != NULL && dot[1] == 'r' && dot[2] != '\0' ) {
						char *end = NULL;
						unsigned long tmp_rid = strtoul( dot + 2, &end, 10 );
						if ( end[0] == '\0' ) {
							rid = (uint16_t)tmp_rid;
							*dot = '\0';
						}
					}
				}
			}
		} else {
			client_version = serializer_get_uint16( &payload );
			image_name = serializer_get_string( &payload );
			rid = serializer_get_uint16( &payload );
			flags = serializer_get_uint8( &payload );
		}
		client->isServer = ( flags & FLAGS8_SERVER );
		if ( unlikely( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) ) {
			if ( client_version < MIN_SUPPORTED_CLIENT ) {
				logadd( LOG_DEBUG1, "Client %s too old", client->hostName );
			} else {
				logadd( LOG_DEBUG1, "Incomplete handshake received from %s", client->hostName );
			}
		} else {
			if ( !client->isServer || !_isProxy ) {
				// Is a normal client, or we're not proxy
				image = image_getOrLoad( image_name, rid );
			} else if ( _backgroundReplication != BGR_FULL && ( flags & FLAGS8_BG_REP ) ) {
				// We're a proxy, client is another proxy, we don't do BGR, but connecting proxy does...
				// Reject, as this would basically force this proxy to do BGR too.
				image = image_get( image_name, rid, true );
				if ( image != NULL && image->ref_cacheMap != NULL ) {
					// Only exception is if the image is complete locally
					image = image_release( image );
				}
			} else if ( _lookupMissingForProxy ) {
				// No BGR mismatch and we're told to lookup missing images on a known uplink server
				// if the requesting client is a proxy
				image = image_getOrLoad( image_name, rid );
			} else {
				// No BGR mismatch, but don't lookup if image is unknown locally
				image = image_get( image_name, rid, true );
			}
			client->image = image;
			atomic_thread_fence( memory_order_release );
			if ( unlikely( image == NULL ) ) {
				//logadd( LOG_DEBUG1, "Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
			} else if ( unlikely( image->problem.read || image->problem.changed ) ) {
				logadd( LOG_DEBUG1, "Client %s requested non-working image '%s' (rid:%d), rejected\n",
						client->hostName, image_name, (int)rid );
			} else {
				// Image is fine so far, but occasionally drop a client if the uplink for the image is clogged or unavailable
				bOk = true;
				if ( image->ref_cacheMap != NULL ) {
					if ( image->problem.queue || image->problem.write ) {
						bOk = ( rand() % 4 ) == 1;
					}
					if ( bOk ) {
						if ( image->problem.write ) { // Wait 100ms if local caching is not working so this
							usleep( 100000 ); // server gets a penalty and is less likely to be selected
						}
						if ( image->problem.uplink ) {
							// Penaltize depending on completeness, if no uplink is available
							usleep( ( 100 - image->completenessEstimate ) * 100 );
						}
					}
				}
				if ( bOk ) {
					mutex_lock( &image->lock );
					image_file = image->readFd;
					if ( !client->isServer ) {
						// Only update immediately if this is a client. Servers are handled on disconnect.
						timing_get( &image->atime );
						image->accessed = true;
					}
					mutex_unlock( &image->lock );
					serializer_reset_write( &payload );
					if (client->iscsi) {
						serializer_put_string( &payload, "TargetPortalGroupTag=1" );
						serializer_put_string( &payload, "HeaderDigest=None" );
						serializer_put_string( &payload, "DataDigest=None" );
						serializer_put_string( &payload, "DefaultTime2Wait=2" );
						serializer_put_string( &payload, "DefaultTime2Retain=0" );
						serializer_put_string( &payload, "IFMarker=No" );
						serializer_put_string( &payload, "OFMarker=No" );
						serializer_put_string( &payload, "ErrorRecoveryLevel=0" );
						serializer_put_string( &payload, "InitialR2T=Yes" );
						serializer_put_string( &payload, "ImmediateData=Yes" );
						serializer_put_string( &payload, "MaxBurstLength=262144" );
						serializer_put_string( &payload, "FirstBurstLength=65536" );
						serializer_put_string( &payload, "MaxOutstandingR2T=1" );
						serializer_put_string( &payload, "MaxConnections=1" );
						serializer_put_string( &payload, "DataPDUInOrder=Yes" );
						serializer_put_string( &payload, "DataSequenceInOrder=Yes" );
					} else {
						serializer_put_uint16( &payload, client_version < 3 ? client_version : PROTOCOL_VERSION ); // XXX: Since messed up fuse client was messed up before :(
						serializer_put_string( &payload, image->name );
						serializer_put_uint16( &payload, (uint16_t)image->rid );
						serializer_put_uint64( &payload, image->virtualFilesize );
					}
					reply.cmd = CMD_SELECT_IMAGE;
					reply.handle = request.handle;
					reply.size = serializer_get_written_length( &payload );
					if ( !send_reply( client, &reply, &payload ) ) {
						bOk = false;
					}
				}
			}
		}
	}

	if ( likely( bOk ) ) {
		// add artificial delay if applicable
		if ( client->isServer && _serverPenalty != 0 ) {
			usleep( _serverPenalty );
		} else if ( !client->isServer && _clientPenalty != 0 ) {
			usleep( _clientPenalty );
		}
		// client handling mainloop
		while ( recv_request_header( client, &request ) ) {
			if ( _shutdown ) break;
			reply.handle = request.handle;
			if ( likely ( request.cmd == CMD_GET_BLOCK ) ) {

				const uint64_t offset = request.offset_small; // Copy to full uint64 to prevent repeated masking
				if ( unlikely( offset >= image->virtualFilesize ) ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested non-existent block", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client, &reply, NULL );
					continue;
				}
				if ( unlikely( offset + request.size > image->virtualFilesize ) ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested data block that extends beyond image size", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client, &reply, NULL );
					continue;
				}

				if ( cache == NULL ) {
					cache = ref_get_cachemap( image );
				}

				if ( request.size != 0 && cache != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					const uint64_t start = offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					const uint64_t end = (offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					if ( !image_isRangeCachedUnsafe( cache, start, end ) ) {
						if ( unlikely( client->relayedCount > 250 ) ) {
							logadd( LOG_DEBUG1, "Client is overloading uplink; throttling" );
							for ( int i = 0; i < 100 && client->relayedCount > 200; ++i ) {
								usleep( 10000 );
							}
							if ( client->relayedCount > 250 ) {
								logadd( LOG_WARNING, "Could not lower client's uplink backlog; dropping client" );
								goto exit_client_cleanup;
							}
						}
						client->relayedCount++;
						if ( !uplink_requestClient( client, &uplinkCallback, request.handle, offset, request.size, request.hops ) ) {
							client->relayedCount--;
							logadd( LOG_DEBUG1, "Could not relay uncached request from %s to upstream proxy for image %s:%d",
									client->hostName, image->name, image->rid );
							goto exit_client_cleanup;
						}
						continue; // Reply arrives on uplink some time later, handle next request now
					}
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;

				if ( !client->iscsi ) fixup_reply( reply );
				const bool lock = image->uplinkref != NULL;
				if ( lock ) mutex_lock( &client->sendMutex );
				// Send reply header
				if ( client->iscsi ? !send_reply( client, &reply, NULL ) : send( client->sock, &reply, sizeof(dnbd3_reply_t), (request.size == 0 ? 0 : MSG_MORE) ) != sizeof(dnbd3_reply_t) ) {
					if ( lock ) mutex_unlock( &client->sendMutex );
					logadd( LOG_DEBUG1, "Sending CMD_GET_BLOCK reply header to %s failed", client->hostName );
					goto exit_client_cleanup;
				}

				if ( request.size != 0 ) {
					// Send payload if request length > 0
					size_t done = 0;
					off_t foffset = (off_t)offset;
					size_t realBytes;
					if ( offset + request.size <= image->realFilesize ) {
						realBytes = request.size;
					} else {
						realBytes = (size_t)(image->realFilesize - offset);
					}
					while ( done < realBytes ) {
						// TODO: Should we consider EOPNOTSUPP on BSD for sendfile and fallback to read/write?
						// Linux would set EINVAL or ENOSYS instead, which it unfortunately also does for a couple of other failures :/
						// read/write would kill performance anyways so a fallback would probably be of little use either way.
#ifdef DNBD3_SERVER_AFL
						char buf[1000];
						size_t cnt = realBytes - done;
						if ( cnt > 1000 ) {
							cnt = 1000;
						}
						const ssize_t sent = pread( image_file, buf, cnt, foffset );
						if ( sent > 0 ) {
							//write( client->sock, buf, sent ); // This is not verified in any way, so why even do it...
						} else {
							const int err = errno;
#elif defined(__linux__)
						const ssize_t sent = sendfile( client->sock, image_file, &foffset, realBytes - done );
						if ( sent <= 0 ) {
							const int err = errno;
#elif defined(__FreeBSD__)
						off_t sent;
						const int ret = sendfile( image_file, client->sock, foffset, realBytes - done, NULL, &sent, 0 );
						if ( ret == -1 || sent == 0 ) {
							const int err = errno;
							if ( ret == -1 ) {
								if ( err == EAGAIN || err == EINTR ) { // EBUSY? manpage doesn't explicitly mention *sent here.. But then again we dont set the according flag anyways
									done += sent;
									continue;
								}
								sent = -1;
							}
#endif
							if ( lock ) mutex_unlock( &client->sendMutex );
							if ( sent == -1 ) {
								if ( err != EPIPE && err != ECONNRESET && err != ESHUTDOWN
										&& err != EAGAIN && err != EWOULDBLOCK ) {
									logadd( LOG_DEBUG1, "sendfile to %s failed (image to net. sent %d/%d, errno=%d)",
											client->hostName, (int)done, (int)realBytes, err );
								}
								if ( err == EBADF || err == EFAULT || err == EINVAL || err == EIO ) {
									logadd( LOG_INFO, "Disabling %s:%d", image->name, image->rid );
									image->problem.read = true;
								}
							}
							goto exit_client_cleanup;
						}
						done += sent;
					}
					if ( request.size > (uint32_t)realBytes ) {
						if ( !sendPadding( client->sock, request.size - (uint32_t)realBytes ) ) {
							if ( lock ) mutex_unlock( &client->sendMutex );
							goto exit_client_cleanup;
						}
					}
				}
				if ( lock ) mutex_unlock( &client->sendMutex );
				// Global per-client counter
				client->bytesSent += request.size; // Increase counter for statistics.
				continue;
			}
			// Any other command
			// Release cache map every now and then, in case the image was replicated
			// entirely. Will be re-grabbed on next CMD_GET_BLOCK otherwise.
			if ( cache != NULL ) {
				ref_put( &cache->reference );
				cache = NULL;
			}
			switch ( request.cmd ) {

			case CMD_GET_SERVERS:
				// Build list of known working alt servers
				num = altservers_getListForClient( client, server_list, NUMBER_SERVERS );
				reply.cmd = CMD_GET_SERVERS;
				reply.size = (uint32_t)( num * sizeof(dnbd3_server_entry_t) );
				mutex_lock( &client->sendMutex );
				send_reply( client, &reply, server_list );
				mutex_unlock( &client->sendMutex );
				goto set_name;
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				mutex_lock( &client->sendMutex );
				send_reply( client, &reply, NULL );
				mutex_unlock( &client->sendMutex );
set_name: ;
				if ( !hasName ) {
					hasName = true;
					setThreadName( client->hostName );
				}
				break;

			case CMD_SET_CLIENT_MODE:
				client->isServer = false;
				break;

			case CMD_GET_CRC32:
				reply.cmd = CMD_GET_CRC32;
				mutex_lock( &client->sendMutex );
				if ( image->crc32 == NULL ) {
					reply.size = 0;
					send_reply( client, &reply, NULL );
				} else {
					const uint32_t size = reply.size = (uint32_t)( (IMGSIZE_TO_HASHBLOCKS(image->realFilesize) + 1) * sizeof(uint32_t) );
					send_reply( client, &reply, NULL );
					send( client->sock, &image->masterCrc32, sizeof(uint32_t), MSG_MORE );
					send( client->sock, image->crc32, size - sizeof(uint32_t), 0 );
				}
				mutex_unlock( &client->sendMutex );
				break;

			default:
				logadd( LOG_ERROR, "Unknown command from client %s: %d", client->hostName, (int)request.cmd );
				break;

			} // end switch
		} // end loop
	} // end bOk
exit_client_cleanup: ;
	// First remove from list, then add to counter to prevent race condition
	removeFromList( client );
	totalBytesSent += client->bytesSent;
	// Access time, but only if client didn't just probe
	if ( image != NULL && client->bytesSent > DNBD3_BLOCK_SIZE * 10 ) {
		mutex_lock( &image->lock );
		timing_get( &image->atime );
		image->accessed = true;
		mutex_unlock( &image->lock );
	}
	if ( cache != NULL ) {
		ref_put( &cache->reference );
	}
	freeClientStruct( client ); // This will also call image_release on client->image
	return NULL ;
fail_preadd: ;
	// This is before we even initialized any mutex
	close( client->sock );
	free( client );
	return NULL;
}

/**
 * Get list of all clients.
 */
struct json_t* net_getListAsJson()
{
	json_t *jsonClients = json_array();
	json_t *clientStats;
	int imgId, isServer;
	uint64_t bytesSent;
	char host[HOSTNAMELEN];
	host[HOSTNAMELEN-1] = '\0';

	mutex_lock( &_clients_lock );
	for ( int i = 0; i < _num_clients; ++i ) {
		dnbd3_client_t * const client = _clients[i];
		if ( client == NULL || client->image == NULL )
			continue;
		mutex_lock( &client->lock );
		// Unlock so we give other threads a chance to access the client list.
		// We might not get an atomic snapshot of the currently connected clients,
		// but that doesn't really make a difference anyways.
		mutex_unlock( &_clients_lock );
		strncpy( host, client->hostName, HOSTNAMELEN - 1 );
		imgId = client->image->id;
		isServer = (int)client->isServer;
		bytesSent = client->bytesSent;
		mutex_unlock( &client->lock );
		clientStats = json_pack( "{sssisisI}",
				"address", host,
				"imageId", imgId,
				"isServer", isServer,
				"bytesSent", (json_int_t)bytesSent );
		json_array_append_new( jsonClients, clientStats );
		mutex_lock( &_clients_lock );
	}
	mutex_unlock( &_clients_lock );
	return jsonClients;
}

/**
 * Get number of clients connected, total bytes sent, or both.
 * we don't unlock the list while iterating or we might get an
 * incorrect result if a client is disconnecting while iterating.
 */
void net_getStats(int *clientCount, int *serverCount, uint64_t *bytesSent)
{
	int cc = 0, sc = 0;
	uint64_t bs = 0;

	mutex_lock( &_clients_lock );
	for ( int i = 0; i < _num_clients; ++i ) {
		const dnbd3_client_t * const client = _clients[i];
		if ( client == NULL || client->image == NULL )
			continue;
		if ( client->isServer ) {
			sc += 1;
		} else {
			cc += 1;
		}
		bs += client->bytesSent;
	}
	// Do this before unlocking the list, otherwise we might
	// account for a client twice if it would disconnect after
	// unlocking but before we add the count here.
	if ( bytesSent != NULL ) {
		*bytesSent = totalBytesSent + bs;
	}
	mutex_unlock( &_clients_lock );
	if ( clientCount != NULL ) {
		*clientCount = cc;
	}
	if ( serverCount != NULL ) {
		*serverCount = sc;
	}
}

void net_disconnectAll()
{
	int i;
	mutex_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] == NULL )
			continue;
		shutdown( _clients[i]->sock, SHUT_RDWR );
		pthread_kill( _clients[i]->thread, SIGINT );
	}
	mutex_unlock( &_clients_lock );
}

void net_waitForAllDisconnected()
{
	int retries = 10, count, i;
	do {
		count = 0;
		mutex_lock( &_clients_lock );
		for (i = 0; i < _num_clients; ++i) {
			if ( _clients[i] == NULL ) continue;
			count++;
		}
		mutex_unlock( &_clients_lock );
		if ( count != 0 ) {
			logadd( LOG_INFO, "%d clients still active...\n", count );
			sleep( 1 );
		}
	} while ( count != 0 && --retries > 0 );
	_num_clients = 0;
}

/* +++
 * Client list.
 *
 * Adding and removing clients.
 */

/**
 * Remove a client from the clients array
 * Locks on: _clients_lock
 */
static void removeFromList(dnbd3_client_t *client)
{
	int i;
	mutex_lock( &_clients_lock );
	if ( _num_clients != 0 ) {
		for ( i = _num_clients - 1; i >= 0; --i ) {
			if ( _clients[i] == client ) {
				_clients[i] = NULL;
				break;
			}
		}
		if ( i != 0 && i + 1 == _num_clients ) {
			do {
				i--;
			} while ( _clients[i] == NULL && i > 0 );
			_num_clients = i + 1;
		}
	}
	mutex_unlock( &_clients_lock );
}

/**
 * Free the client struct recursively.
 * !! Make sure to call this function after removing the client from _dnbd3_clients !!
 * Locks on: _clients[].lock, _images[].lock
 * might call functions that lock on _images, _image[], uplink.queueLock, client.sendMutex
 */
static dnbd3_client_t* freeClientStruct(dnbd3_client_t *client)
{
	mutex_lock( &client->lock );
	if ( client->image != NULL ) {
		dnbd3_uplink_t *uplink = ref_get_uplink( &client->image->uplinkref );
		if ( uplink != NULL ) {
			if ( client->relayedCount != 0 ) {
				uplink_removeEntry( uplink, client, &uplinkCallback );
			}
			ref_put( &uplink->reference );
		}
		if ( client->relayedCount != 0 ) {
			logadd( LOG_DEBUG1, "Client has relayedCount == %"PRIu8" on disconnect..", client->relayedCount );
			int i;
			for ( i = 0; i < 1000 && client->relayedCount != 0; ++i ) {
				usleep( 10000 );
			}
			if ( client->relayedCount != 0 ) {
				logadd( LOG_WARNING, "Client relayedCount still %"PRIu8" after sleeping!", client->relayedCount );
			}
		}
	}
	mutex_lock( &client->sendMutex );
	if ( client->sock != -1 ) {
		close( client->sock );
	}
	client->sock = -1;
	mutex_unlock( &client->sendMutex );
	mutex_unlock( &client->lock );
	client->image = image_release( client->image );
	mutex_destroy( &client->lock );
	mutex_destroy( &client->sendMutex );
	free( client );
	return NULL ;
}

//###//

/**
 * Add client to the clients array.
 * Locks on: _clients_lock
 */
static bool addToList(dnbd3_client_t *client)
{
	int i;
	mutex_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] != NULL ) continue;
		_clients[i] = client;
		mutex_unlock( &_clients_lock );
		return true;
	}
	if ( _num_clients >= _maxClients ) {
		mutex_unlock( &_clients_lock );
		logadd( LOG_ERROR, "Maximum number of clients reached!" );
		return false;
	}
	_clients[_num_clients++] = client;
	mutex_unlock( &_clients_lock );
	return true;
}

static void uplinkCallback(void *data, uint64_t handle, uint64_t start UNUSED, uint32_t length, const char *buffer)
{
	dnbd3_client_t *client = (dnbd3_client_t*)data;
	dnbd3_reply_t reply = {
		.magic = dnbd3_packet_magic,
		.cmd = buffer == NULL ? CMD_ERROR : CMD_GET_BLOCK,
		.handle = handle,
		.size = length,
	};
	mutex_lock( &client->sendMutex );
	send_reply( client, &reply, buffer );
	if ( buffer == NULL ) {
		shutdown( client->sock, SHUT_RDWR );
	}
	client->relayedCount--;
	mutex_unlock( &client->sendMutex );
}

