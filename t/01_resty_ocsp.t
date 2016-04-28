use Test::Nginx::Socket::Lua 'no_plan';

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_shuffle();

run_tests();

__DATA__

=== TEST 1: get OCSP response (ocsp responder not found)
--- http_config
    lua_package_path "./lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/chain/chain.pem"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local ocsp_resp = ocsp.get_ocsp_response(cert_data)
            if not ocsp_resp then
                return
            end

            ngx.log(ngx.WARN, "get ocsp response success")
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
OCSP responder not found

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 2: get OCSP response (empty string cert)
--- http_config
    lua_package_path "./lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/chain.pem"))
            local cert_data = f:read("*a")
            f:close()

            local cert_data = ""
            local ocsp_resp = ocsp.get_ocsp_response(cert_data)
            if not ocsp_resp then
                return
            end
            ngx.log(ngx.WARN, "get ocsp response success")
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
failed to create OCSP request: d2i_X509_bio() failed

--- no_error_log
[alert]
[emerg]


=== TEST 3: get ocsp response (no issuer cert in the chain)
--- http_config
    lua_package_path "./lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/test-com.crt"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local req, err = ocsp.get_ocsp_response(cert_data)
            if not req then
                return
            end 
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
failed to create OCSP request: no issuer certificate in chain

--- no_error_log
[alert]
[emerg]


=== TEST 4: validate good OCSP response
--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        resolver $TEST_NGINX_RESOLVER;
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/ssl_tianchaijz.pem"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local resp = ocsp.get_ocsp_response(cert_data) 

            local req, err = ocsp.validate_ocsp_response(resp, cert_data)
            if not req then
                ngx.log(ngx.ERR, "failed to validate OCSP response: ", err)
                return
            end

            ngx.log(ngx.WARN, "OCSP response validation ok")
        ';
        
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
OCSP response validation ok

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 5: validate good OCSP response - no certs in response
--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/chain.pem"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local f = assert(io.open("t/cert/ocsp/ocsp-resp-no-certs.der"))
            local resp = f:read("*a")
            f:close()

            local req, err = ocsp.validate_ocsp_response(resp, cert_data)
            if not req then
                ngx.log(ngx.ERR, "failed to validate OCSP response: ", err)
                return
            end

            ngx.log(ngx.WARN, "OCSP response validation ok")
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
OCSP response validation ok

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 6: validate OCSP response - OCSP response signed by an unknown cert and the OCSP response contains the unknown cert

FIXME: we should complain in this case.

--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/chain.pem"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local f = assert(io.open("t/cert/ocsp/ocsp-resp-signed-by-orphaned.der"))
            local resp = f:read("*a")
            f:close()

            local req, err = ocsp.validate_ocsp_response(resp, cert_data)
            if not req then
                ngx.log(ngx.ERR, "failed to validate OCSP response: ", err)
                return
            end

            ngx.log(ngx.WARN, "OCSP response validation ok")
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
OCSP response validation ok

--- no_error_log
[error]
[alert]
[emerg]



=== TEST 7: fail to validate OCSP response - OCSP response signed by an unknown cert and the OCSP response does not contain the unknown cert

--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name   test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/chain.pem"))
            local cert_data = f:read("*a")
            f:close()

            cert_data, err = ssl.cert_pem_to_der(cert_data)
            if not cert_data then
                ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
                return
            end

            local f = assert(io.open("t/cert/ocsp/ocsp-resp-signed-by-orphaned-no-certs.der"))
            local resp = f:read("*a")
            f:close()

            local req, err = ssl.validate_ocsp_response(resp, cert_data)
            if not req then
                ngx.log(ngx.ERR, "failed to validate OCSP response: ", err)
                return
            end

            ngx.log(ngx.WARN, "OCSP response validation ok")
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key; 
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
failed to validate OCSP response: OCSP_basic_verify() failed

--- no_error_log
OCSP response validation ok
[alert]
[emerg]


=== TEST 9: good status req from client
FIXME: check the OCSP staple actually received by the ssl client
--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        listen 127.0.0.2:8080 ssl;
        server_name test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"
            
            local f = assert(io.open("t/cert/ocsp/ocsp-resp.der"))
            local resp = assert(f:read("*a"))
            f:close()

            print("resp len: ", #resp)

            local ok, err = ocsp.set_ocsp_status_resp(resp)
            if not ok then
                ngx.log(ngx.ERR, "failed to set ocsp status resp: ", err)
                return
            end
            ngx.log(ngx.WARN, "ocsp status resp set ok: ", err)
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("127.0.0.2", 8080)
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true, true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
ocsp status resp set ok: nil,

--- no_error_log
[error]
[alert]
[emerg]



=== TEST 10: no status req from client
--- http_config
    lua_package_path "./lib/?.lua;lua/?.lua;../lua-resty-core/lib/?.lua;;";

    server {
        listen 127.0.0.2:8080 ssl;
        server_name test.com;
        ssl_certificate_by_lua '
            local ssl = require "ngx.ssl"
            local ocsp = require "resty.ocsp"

            local f = assert(io.open("t/cert/ocsp/ocsp-resp.der"))
            local resp = assert(f:read("*a"))
            f:close()

            print("resp len: ", #resp)

            local ok, err = ocsp.set_ocsp_status_resp(resp)
            if not ok then
                ngx.log(ngx.ERR, "failed to set ocsp status resp: ", err)
                return
            end
            ngx.log(ngx.WARN, "ocsp status resp set ok: ", err)
        ';
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
    }
--- config
    server_tokens off;
    resolver $TEST_NGINX_RESOLVER;
    lua_ssl_trusted_certificate ../../cert/test.crt;
    lua_ssl_verify_depth 3;

    location /t {
        #set $port 5000;
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua '
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(2000)

                local ok, err = sock:connect("127.0.0.2", 8080)
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true, false)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))
            end  -- do
        ';
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: userdata

--- error_log
ocsp status resp set ok: no status req,

--- no_error_log
[error]
[alert]
[emerg]
