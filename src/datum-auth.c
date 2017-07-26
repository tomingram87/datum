#include <kore/kore.h>
#include <kore/http.h>
#include <cjose/cjose.h>
#include <openssl/rand.h>
#include <openssl/rand.h>
#include <jansson.h>

#include <string.h>

#include "assets.h"
#include "datum-auth.h"

// TODO move these keys to file
static const char *EC_P256_d = "RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM";
static const char *EC_P256_x = "ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk";
static const char *EC_P256_y = "KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM";

static const char *DATUM_HDR_KID_VAL = "datum";
static const char *DATUM_CLAIM_ISSUER = "iss";
static const char *DATUM_CLAIM_SUBJECT = "sub";
static const char *DATUM_CLAIM_AUDIENCE = "aud";
static const char *DATUM_CLAIM_EXPIRATION_TIME = "exp";
static const char *DATUM_CLAIM_NOT_BEFORE = "nbf";
static const char *DATUM_CLAIM_ISSUED_AT = "iat";
static const char *DATUM_CLAIM_JWT_ID = "jti";
static const char *DATUM_XSRF_HEADER = "x-xsrf-token";


static int
http_response_header_datum(struct http_request *req, const char *username);

static int
http_request_header_authorization(struct http_request *req, char **username, char **password);

static cjose_jwk_t *
create_key (void);

static char *
create_token (char *nonce, const char* host, const char *username, const char *origin);

static char *
create_nonce (void);

static char *
create_timestamp (int offset);


int
login(struct http_request *req)
{
	char *username;
	char *password;

	if (!http_request_header_authorization(req, &username, &password))
	{
		kore_log(LOG_WARNING, "no authorization in request header");
		return (KORE_RESULT_ERROR);
	}

	// TODO check credentials against database
	if (strcmp(username, password) == 0)
	{
		http_response_header_datum(req, username);
		http_response(req, 200, NULL, 0);

		return (KORE_RESULT_OK);
	}

	return (KORE_RESULT_ERROR);
}

int
authenticated(struct http_request *req)
{
	http_response(req, 200, NULL, 0);

	return (KORE_RESULT_OK);
}

int
logout(struct http_request *req)
{
	http_response_header(req, "set-cookie", "sessid=null");
	http_response(req, 200, NULL, 0);

	return (KORE_RESULT_OK);
}

int
v_session_public(struct http_request *req, char *data)
{
	http_response_header_datum(req, "guest");

	return (KORE_RESULT_OK);
}

int
v_session_private(struct http_request *req, char *data)
{
	int result = KORE_RESULT_ERROR;

	cjose_err jose_err;
	json_error_t json_err;
	cjose_jwk_t *jwk;
	cjose_jws_t *jws;
	json_t *claims;
	char *json;
	char *timestamp;
	char *origin;
	char *xsrfid;
	size_t data_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	const char *issuer;
	const char *subject;
	const char *audience;
	const char *issued_at;
	const char *not_before;
	const char *expiration_time;
	const char *jwt_id;

	// validate header
	if (!req->host)
	{
		kore_log(LOG_WARNING, "no host in request header");
		return (KORE_RESULT_ERROR);
	}

	if (!http_request_header(req, "origin", &origin))
	{
		kore_log(LOG_WARNING, "no origin in request header");
		return (KORE_RESULT_ERROR);
	}

	if (!http_request_header(req, "x-xsrf-token", &xsrfid))
	{
		kore_log(LOG_WARNING, "no x-xsrf-token in request header");
		return (KORE_RESULT_ERROR);
	}

	// validate jws
	data_len = strlen(data) + 1;

  jwk = create_key();
	jws = cjose_jws_import(data, data_len, &jose_err);

	if (!cjose_jws_verify(jws, jwk, &jose_err))
	{
		kore_log(LOG_WARNING, "unable to verify session token");
		cjose_jws_release(jws);
		cjose_jwk_release(jwk);
		return (KORE_RESULT_ERROR);
	}

	if (!cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &jose_err))
	{
		kore_log(LOG_WARNING, "unable to get plaintext from token");
		cjose_jws_release(jws);
		cjose_jwk_release(jwk);
		return (KORE_RESULT_ERROR);
	}
	else
	{
		json = kore_malloc(plaintext_len + 1);
		kore_strlcpy(json, (char *)plaintext, plaintext_len + 1);

		cjose_jws_release(jws);
		cjose_jwk_release(jwk);
	}

	claims = json_loads((char *)json, 0, &json_err);

	issuer = json_string_value(json_object_get(claims, DATUM_CLAIM_ISSUER));
	if (strcmp(issuer, req->host) != 0)
	{
		kore_log(LOG_WARNING, "host does not equal issuer");
		return (KORE_RESULT_ERROR);
	}

	audience = json_string_value(json_object_get(claims, DATUM_CLAIM_AUDIENCE));
	if (strcmp(audience, origin) != 0)
	{
		kore_log(LOG_WARNING, "origin does not equal audience");
		return (KORE_RESULT_ERROR);
	}

	jwt_id = json_string_value(json_object_get(claims, DATUM_CLAIM_JWT_ID));
	if (strcmp(jwt_id, xsrfid) != 0)
	{
		kore_log(LOG_WARNING, "xsrfid does not equal jwt_id");
		return (KORE_RESULT_ERROR);
	}

	timestamp = create_timestamp(0);

	issued_at = json_string_value(json_object_get(claims, DATUM_CLAIM_ISSUED_AT));
	if (strcmp(issued_at, timestamp) >= 0)
	{
		kore_log(LOG_WARNING, "token issued on or before now");
		kore_free(timestamp);
		return (KORE_RESULT_ERROR);
	}

	not_before = json_string_value(json_object_get(claims, DATUM_CLAIM_NOT_BEFORE));
	if (strcmp(not_before, timestamp) >= 0)
	{
		kore_log(LOG_WARNING, "token issued on or before now");
		kore_free(timestamp);
		return (KORE_RESULT_ERROR);
	}

	expiration_time = json_string_value(json_object_get(claims, DATUM_CLAIM_EXPIRATION_TIME));
	if (strcmp(expiration_time, timestamp) < 0)
	{
		kore_log(LOG_WARNING, "token expired");
		kore_free(timestamp);
		return (KORE_RESULT_ERROR);
	}

	subject = json_string_value(json_object_get(claims, DATUM_CLAIM_SUBJECT));

	http_response_header_datum(req, subject);

	kore_free(timestamp);
	kore_free(json);
	// TODO cleanup json & values?

	return (result);
}

static int
http_response_header_datum(struct http_request *req, const char *username)
{
	char *host = NULL;
	char *origin = NULL;
	char *nonce = NULL;
	char *sessid = NULL;
	char *cookie = NULL;
  char *cookie_fmt = NULL;
	size_t cookie_len;

	host = kore_stupdup(req->host);

	if (NULL == host)
	{
		
	}

	origin = kore_stupdup(inet_ntoa(req->owner->addr.ipv4.sin_addr));
	nonce = create_nonce();
	sessid = create_token(nonce, req->host, username, origin);
	cookie_fmt = "sessid=%s;domain=localhost;path=/;secure;httponly;samesite=strict";
	cookie_len = snprintf(NULL, 0, cookie_fmt, sessid) + 1;
	cookie = kore_malloc(cookie_len);

	snprintf(cookie, cookie_len, cookie_fmt, sessid);

	http_response_header(req, DATUM_XSRF_HEADER, nonce);
  http_response_header(req, "set-cookie", cookie);

	kore_free(host);
	kore_free(origin);
	kore_free(cookie);
	kore_free(sessid);
	kore_free(nonce);

	return (KORE_RESULT_OK);
}

static int
http_request_header_authorization(struct http_request *req, char **username, char **password)
{
	cjose_err jose_err;
	char *authorization;
	char *encoded;
	size_t encoded_len;
	uint8_t *decoded;
	size_t decoded_len;
	char *credentials[2];
	size_t offset;

	offset = strlen("basic ");

	if (http_request_header(req, "authorization", &authorization))
	{
		if (strncasecmp(authorization, "basic ", offset) == 0)
		{
			encoded = authorization + offset; // offset encoded pointer
			encoded_len = strlen(encoded);

			if (cjose_base64url_decode(encoded, encoded_len, &decoded, &decoded_len, &jose_err))
			{
				if (kore_split_string((char *)decoded, ":", credentials, 3) == 2)
				{
					*username = kore_strdup(credentials[0]);
					*password = kore_strdup(credentials[1]);

					return (KORE_RESULT_OK);
				}
			}
		}
	}

	return (KORE_RESULT_ERROR);
}

static cjose_jwk_t *
create_key (void)
{
	cjose_err jose_err;
	cjose_jwk_ec_keyspec spec;
	cjose_jwk_t *jwk;

	// create the jwk specification
	memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
	spec.crv = CJOSE_JWK_EC_P_256;
	cjose_base64url_decode(EC_P256_d, strlen(EC_P256_d), &spec.d, &spec.dlen, &jose_err);
	cjose_base64url_decode(EC_P256_x, strlen(EC_P256_x), &spec.x, &spec.xlen, &jose_err);
	cjose_base64url_decode(EC_P256_y, strlen(EC_P256_y), &spec.y, &spec.ylen, &jose_err);

	// create the jwk
	jwk = cjose_jwk_create_EC_spec(&spec, &jose_err);

	return (jwk);
}

static char *
create_token (char *nonce, const char* host, const char *username, const char *origin)
{
	cjose_err jose_err;
	cjose_jwk_t *jwk;
	cjose_header_t *hdr;
	cjose_jws_t *jws;
	char *issued_at;
	char *expiration_time;
	char *format;
	char *payload;
	size_t payload_len;
	const char *serial;
	char *token;

	// create the jws header
	hdr = cjose_header_new(&jose_err);
	cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ES256, &jose_err);
	cjose_header_set(hdr, CJOSE_HDR_KID, DATUM_HDR_KID_VAL, &jose_err);

	// create the jws payload
	issued_at = create_timestamp(0);
	expiration_time = create_timestamp(1800);

	format = "{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\","
						"\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}";

	payload_len = snprintf(NULL, 0, format,
													DATUM_CLAIM_ISSUER, host,
													DATUM_CLAIM_SUBJECT, username,
													DATUM_CLAIM_AUDIENCE, origin,
													DATUM_CLAIM_ISSUED_AT, issued_at,
													DATUM_CLAIM_NOT_BEFORE, issued_at,
													DATUM_CLAIM_EXPIRATION_TIME, expiration_time,
													DATUM_CLAIM_JWT_ID, nonce) + 1;

	payload = kore_malloc(payload_len);

	snprintf(payload, payload_len, format,
							DATUM_CLAIM_ISSUER, host,
							DATUM_CLAIM_SUBJECT, username,
							DATUM_CLAIM_AUDIENCE, origin,
							DATUM_CLAIM_ISSUED_AT, issued_at,
							DATUM_CLAIM_NOT_BEFORE, issued_at,
							DATUM_CLAIM_EXPIRATION_TIME, expiration_time,
							DATUM_CLAIM_JWT_ID, nonce);

	// create the jwk
	jwk = create_key();

	// create the jws
	jws = cjose_jws_sign(jwk, hdr, (uint8_t *)payload, payload_len - 1, &jose_err);

	if (cjose_jws_export(jws, &serial, &jose_err))
	{
		token = kore_strdup(serial);
	}
	else
	{
			token = NULL;
	}

	cjose_jws_release(jws);
	cjose_jwk_release(jwk);
	cjose_header_release(hdr);

	kore_free(payload);
	kore_free(issued_at);
	kore_free(expiration_time);

	return (token);
}

static char *
create_nonce (void)
{
	const int KEY_SIZE = 16;
	const int NONCE_LEN = KEY_SIZE * 2 + 1;
	unsigned char key[KEY_SIZE];
	char *nonce;

	RAND_bytes(key, KEY_SIZE);

	nonce = kore_malloc(NONCE_LEN);

	int i; for (i = 0; i < KEY_SIZE; i++)
	{
    	snprintf(nonce + 2 * i, 3, "%02X", key[i]);
	}

	return (nonce);
}

static char *
create_timestamp (int offset)
{
	time_t now;
	struct tm *t;
	char *timestamp;
	size_t timestamp_len;

	now = time(NULL) + offset;
	t = gmtime(&now);

	timestamp_len = snprintf(NULL, 0, "%04d-%02d-%02dT%02d:%02d:%02dZ",
											     	t->tm_year+1900, t->tm_mon+1, t->tm_mday,
														t->tm_hour, t->tm_min, t->tm_sec) + 1;

	timestamp = kore_malloc(timestamp_len);

	snprintf(timestamp, timestamp_len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
         			t->tm_year+1900, t->tm_mon+1, t->tm_mday,
							t->tm_hour, t->tm_min, t->tm_sec);

	return (timestamp);
}
