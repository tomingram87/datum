#ifndef DATUM_H
#define DATUM_H

int		datum(struct http_request *);

int		css_normalize(struct http_request *);

int		css_skeleton(struct http_request *);

int		js_datum(struct http_request *);

int		js_datum_auth(struct http_request *);

int		js_datum_core(struct http_request *);

int		js_datum_flow(struct http_request *);

int		js_datum_plot(struct http_request *);

int		js_datum_stat(struct http_request *);

int		js_datum_view(struct http_request *);

#endif /* DATUM_H */
