#include <kore/kore.h>
#include <kore/http.h>

#include "assets.h"
#include "datum.h"
#include "datum-auth.h"


int
datum(struct http_request *req)
{
  http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_datum_html, asset_len_datum_html);

	return (KORE_RESULT_OK);
}

int
css_normalize(struct http_request *req)
{
  http_response_header(req, "content-type", "text/css");
	http_response(req, 200, asset_normalize_css, asset_len_normalize_css);

	return (KORE_RESULT_OK);
}

int
css_skeleton(struct http_request *req)
{
  http_response_header(req, "content-type", "text/css");
	http_response(req, 200, asset_skeleton_css, asset_len_skeleton_css);

	return (KORE_RESULT_OK);
}

int
js_datum(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_js, asset_len_datum_js);

	return (KORE_RESULT_OK);
}

int
js_datum_auth(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_auth_js, asset_len_datum_auth_js);

	return (KORE_RESULT_OK);
}

int
js_datum_core(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_core_js, asset_len_datum_core_js);

	return (KORE_RESULT_OK);
}

int
js_datum_flow(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_flow_js, asset_len_datum_flow_js);

	return (KORE_RESULT_OK);
}

int
js_datum_plot(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_plot_js, asset_len_datum_plot_js);

	return (KORE_RESULT_OK);
}

int
js_datum_stat(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_stat_js, asset_len_datum_stat_js);

	return (KORE_RESULT_OK);
}

int
js_datum_view(struct http_request *req)
{
  http_response_header(req, "content-type", "text/javascript");
	http_response(req, 200, asset_datum_view_js, asset_len_datum_view_js);

	return (KORE_RESULT_OK);
}
