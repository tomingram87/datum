#ifndef DATUM_AUTH_H
#define DATUM_AUTH_H


int login(struct http_request *req);

int authenticated(struct http_request *req);

int logout(struct http_request *req);

int v_session_public(struct http_request *req, char *data);

int v_session_private(struct http_request *req, char *data);


#endif /* DATUM_AUTH_H */
