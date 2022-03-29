rule possibleC2malleable_amazonprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable amazon.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: www.amazon.com"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: Server"
		$headerServer1 = "x-amz-id-1: THKUYEZKCKPGY5T42PZT"
		$headerServer2 = "x-amz-id-2: a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRuZ2tmZGl4aHRvNDVpbgo="
		$headerServer3 = "X-Frame-Options: SAMEORIGIN"
		$headerServer4 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_amazonprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable amazon.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/N4215/adj/amzn.us.sr.aps" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: text/xml"
		$headerClient2 = "X-Requested-With: XMLHttpRequest"
		$headerClient3 = "Host: www.amazon.com"
		$headerServer0 = "Server: Server"
		$headerServer1 = "x-amz-id-1: THK9YEZJCKPGY5T42OZT"
		$headerServer2 = "x-amz-id-2: a21JZ1xrNDNtdGRsa219bGV3YW85amZuZW9zdG5rZmRuZ2tmZGl4aHRvNDVpbgo="
		$headerServer3 = "X-Frame-Options: SAMEORIGIN"
		$headerServer4 = "x-ua-compatible: IE=edge"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_apt1_virtuallythereprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable apt1_virtuallythere.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/zOMGAPT" fullword
		$headerServer0 = "Content-Type: application/octet-stream"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_apt1_virtuallythereprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable apt1_virtuallythere.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/BUYTHEAPTDETECTORNOW" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerServer0 = "Content-Type: text/html"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_asproxprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable asprox.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Content-Transfer-Encoding: base64"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx/1.2.5"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "X-Powered-By: PHP/5.4.4-7"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)"

	condition:
		all of ($header*)
}

rule possibleC2malleable_asproxprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable asprox.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/78dc91f1A716DBBAA9E4E12C884C1CB1C27FFF2BEEED7DF1" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Content-Transfer-Encoding: base64"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx/1.2.5"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "X-Powered-By: PHP/5.4.4-7"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_backoffprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable backoff.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/updates" fullword
		$headerClient0 = "Cookie"
		$headerServer0 = "Content-Type: text/plain"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_backoffprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable backoff.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/windebug/updcheck.php" fullword
		$uri1 = "/aircanada/dark.php" fullword
		$uri2 = "/aero2/fly.php" fullword
		$uri3 = "/windowsxp/updcheck.php" fullword
		$uri4 = "/hello/flash.php" fullword
		$headerClient0 = "Accept: text/plain"
		$headerClient1 = "Accept-Language: en-us"
		$headerClient2 = "Accept-Encoding: text/plain"
		$headerClient3 = "Content-Type: application/x-www-form-urlencoded"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bingsearch_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable bingsearch_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/search/" fullword
		$headerClient0 = "Host: www.bing.com"
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient2 = "Cookie: DUP=Q=GpO1nJpMnam4UllEfmeMdg2&T=283767088&A=1&IG"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "Server: Microsoft-IIS/8.5"
		$headerServer4 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bingsearch_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable bingsearch_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Search/" fullword
		$headerClient0 = "Host: www.bing.com"
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient2 = "Cookie: DUP=Q=GpO1nJpMnam4UllEfmeMdg2&T=283767088&A=1&IG"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "Server: Microsoft-IIS/8.5"
		$headerServer4 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bing_mapsprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable bing_maps.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/maps/overlaybfpr" fullword
		$headerClient0 = "Host: www.bing.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US,en;q=0.5"
		$headerClient3 = "Connection: close"
		$headerClient4 = "Cookie"
		$headerServer0 = "Cache-Control: public"
		$headerServer1 = "Content-Type: text/html;charset=utf-8"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "P3P: \"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\""
		$headerServer4 = "X-MSEdge-Ref: Ref A: 20D7023F4A1946FEA6E17C00CC8216CF Ref B: DALEDGE0715"
		$headerServer5 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bing_mapsprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable bing_maps.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/fd/ls/lsp.aspx" fullword
		$headerClient0 = "Host: www.bing.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Content-Type: text/xml"
		$headerClient4 = "Connection: close"
		$headerClient5 = "Cookie"
		$headerServer0 = "Cache-Control: public, max-age=31536000"
		$headerServer1 = "Content-Type: application/json"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "X-Cache: TCO_HIT"
		$headerServer4 = "Server: Microsoft-IIS/10.0"
		$headerServer5 = "X-AspNet-Version: 4.0.30319"
		$headerServer6 = "X-Powered-By: ASP.NET"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bing_mapsprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable bing_maps.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/maps/overlayBFPR" fullword
		$uri1 = "/maps/overlayBfpr" fullword
		$headerClient0 = "Host: www.bing.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US,en;q=0.5"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-Control: public"
		$headerServer1 = "Content-Type: text/html;charset=utf-8"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "P3P: \"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\""
		$headerServer4 = "X-MSEdge-Ref: Ref A: 20D7023F5A1946FFA6E18C00CC8216CF Ref B: DALEDGE0815"
		$headerServer5 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bluenoroff_ratprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable bluenoroff_rat.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/view.jsp" fullword
		$headerClient0 = "Host: update.toythieves.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Cookie: 0449651003fe48-Nff0eb7"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_bluenoroff_ratprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable bluenoroff_rat.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/View.jsp" fullword
		$headerClient0 = "Host: update.toythieves.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Cookie"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_chches_APT10profile_httpget
{
	meta:
		description = "Detects possible C2 malleable chches_APT10.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/5aq/XP/SY75Qyw.htm" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: fukuoka.cloud-maste.com"
		$headerClient2 = "Connection: Keep-Alive"
		$headerClient3 = "Cache-Control: no-cache"
		$headerClient4 = "Cookie"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E )"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_chches_APT10profile_httppost
{
	meta:
		description = "Detects possible C2 malleable chches_APT10.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/RCg/vp6rBcQ.htm" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: fukuoka.cloud-maste.com"
		$headerClient2 = "Connection: Keep-Alive"
		$headerClient3 = "Cache-Control: no-cache'     "
		$headerClient4 = "Cookie"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E )"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_chches_APT10profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable chches_APT10.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ST/TWGRYKf0/d/du92w/RUk/Z2l.htm" fullword
		$uri1 = "/ST/TWGRYkf0/d/du92w/RUk/Z2l.htm" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: fukuoka.cloud-maste.com"
		$headerClient2 = "Connection: Keep-Alive"
		$headerClient3 = "Cache-Control: no-cache"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E )"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_cnnvideo_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable cnnvideo_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/cnn/cnnx/dai/hds/stream_hd/1/cnnxlive1_4.bootstrap" fullword
		$headerClient0 = "Host: phds-live.cdn.turner.com"
		$headerClient1 = "X-Requested-With: ShockwaveFlash/24.0.0.186"
		$headerClient2 = "Referer: http://go.cnn.com/?stream=cnn&sr=watchHPbutton"
		$headerServer0 = "Server: ngx_openresty"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "ETag: dbbece0334279b5bfbf88c27bda56444"
		$headerServer3 = "Cache-Control: max-age=1"
		$headerServer4 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_cnnvideo_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable cnnvideo_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/cnn/cnnx/dai/hds/stream_hd/2/cnnxlive1_4.bootstrap" fullword
		$headerClient0 = "Host: phds-live.cdn.turner.com"
		$headerClient1 = "X-Requested-With: ShockwaveFlash/24.0.0.186"
		$headerClient2 = "Referer"
		$headerServer0 = "Server: ngx_openresty"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "ETag: dbbece0334279b5bfbf88c27bda56444"
		$headerServer3 = "Cache-Control: max-age=1"
		$headerServer4 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_comfooprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable comfoo.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/CWoNaJLBo/VTNeWw11212/" fullword
		$headerClient0 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
		$headerClient1 = "Accept-Language: en-en"
		$headerClient2 = "Connection: Keel-Alive"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Server: Apache/2.0.50 (Unix)"
		$headerServer1 = "Keep-Alive: timeout=15, max=90"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_comfooprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable comfoo.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/CWoNaJLBo/VTNeWw11213/" fullword
		$headerClient0 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
		$headerClient1 = "Accept-Language: en-en"
		$headerClient2 = "Connection: Keel-Alive"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Server: Apache/2.0.50 (Unix)"
		$headerServer1 = "Keep-Alive: timeout=15, max=90"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_covid19_koadicprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable covid19_koadic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/auto.cfg.bat" fullword
		$headerClient0 = "Host: 216.189.145.11"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: Apache/2.2.22 (Ubuntu)"
		$headerServer1 = "Last-Modified: Thu, 05 Mar 2020 01:46:51 GMT"
		$headerServer2 = "ETag: 41fc-e159-5a011b5f258c0"
		$headerServer3 = "Accept-Ranges: bytes"
		$headerServer4 = "Keep-Alive: timeout=5, max=100"
		$headerServer5 = "Connection: Keep-Alive"
		$headerServer6 = "Content-Type: application/x-msdos-program"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_covid19_koadicprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable covid19_koadic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/html" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Referer: http://googlechromeupdater.twilightparadox.com:448/html"
		$headerClient2 = "encoder: 1252"
		$headerClient3 = "shellchcp: 437"
		$headerClient4 = "Host: googlechromeupdater.twilightparadox.com:448"
		$headerServer0 = "Server: Apache"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_covid19_koadicprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable covid19_koadic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/RECOMMENDATIONS_CORONAVIRUS.doc" fullword
		$uri1 = "/Recommendations_Coronavirus.doc" fullword
		$headerClient0 = "Host: 216.189.145.11"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache/2.2.22 (Ubuntu)"
		$headerServer1 = "Keep-Alive: timeout=5, max=100"
		$headerServer2 = "Connection: Keep-Alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_covid19_koadicprofile_httpgetvariant
{
	meta:
		description = "Detects possible C2 malleable covid19_koadic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/HTML" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: googlechromeupdater.twilightparadox.com:448"
		$headerClient2 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_defaultprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable default.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ca" fullword
		$uri1 = "/dpixel" fullword
		$uri2 = "/__utm.gif" fullword
		$uri3 = "/pixel.gif" fullword
		$uri4 = "/g.pixel" fullword
		$uri5 = "/dot.gif" fullword
		$uri6 = "/updates.rss" fullword
		$uri7 = "/fwlink" fullword
		$uri8 = "/cm" fullword
		$uri9 = "/cx" fullword
		$uri10 = "/pixel" fullword
		$uri11 = "/match" fullword
		$uri12 = "/visit.js" fullword
		$uri13 = "/load" fullword
		$uri14 = "/push" fullword
		$uri15 = "/ptj" fullword
		$uri16 = "/j.ad" fullword
		$uri17 = "/ga.js" fullword
		$uri18 = "/en_US/all.js" fullword
		$uri19 = "/activity" fullword
		$uri20 = "/IE9CompatViewList.xml" fullword
		$headerClient0 = "Cookie"
		$headerServer0 = "Content-Type: application/octet-stream"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_defaultprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable default.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/submit.php" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerServer0 = "Content-Type: text/html"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_emotetprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable emotet.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/LSnmkxT/" fullword
		$headerClient0 = "Host: trevorcameron.com"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "Cache-Control: no-cache, no-store, max-age=0, must-revalidate"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Content-Disposition: attachment; filename='NFccF.exe"
		$headerServer4 = "Content-Transfer-Encoding: binary"
		$headerServer5 = "Keep-Alive: timeout=2, max=100"
		$headerServer6 = "Connection: Keep-Alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_emotetprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable emotet.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/LSnmkXT/" fullword
		$headerClient0 = "Host: 77.244.37:7080"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cache-Control: no-cache"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_emotetprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable emotet.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ckgawd/" fullword
		$uri1 = "/Ckgawd/" fullword
		$headerClient0 = "Host: blushphotoandfilm.com"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Cache-Control: Cache-Control: no-cache, no-store, max-age=0, must-revalidate"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "Server: Apache"
		$headerServer3 = "Connection: Keep-Alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_etumbotprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable etumbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/image/" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*l;q=0.8"
		$headerClient1 = "Referer: http://www.google.com"
		$headerClient2 = "Pragma: no-cache"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Content-Type: img/jpg"
		$headerServer1 = "Server: Microsoft-IIS/6.0"
		$headerServer2 = "X-Powered-By: ASP.NET"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_etumbotprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable etumbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/history/" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerClient1 = "Referer: http://www.google.com"
		$headerClient2 = "Pragma: no-cache"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Content-Type: img/jpg"
		$headerServer1 = "Server: Microsoft-IIS/6.0"
		$headerServer2 = "X-Powered-By: ASP.NET"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_fiestaprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable fiesta.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/rmvk30g/" fullword
		$headerClient0 = "Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"
		$headerClient1 = "Connection: keep-alive"
		$headerServer0 = "Server: Apache/2.2.15 (CentOS)"
		$headerServer1 = "X-Powered-By: PHP/5.3.27"
		$headerServer2 = "Content-Type: application/octet-stream"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (Windows 7 6.1) Java/1.7.0_11"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_fiestaprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable fiesta.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerServer0 = "Server: nginx/1.4.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/6.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; InfoPath.3; .NET4.0C; .NET4.0E)"

	condition:
		all of ($header*)
}

rule possibleC2malleable_fiesta2profile_httpget
{
	meta:
		description = "Detects possible C2 malleable fiesta2.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/v20idaf/" fullword
		$headerClient0 = "Accept: */*"
		$headerServer0 = "Server: nginx/1.4.4"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_fiesta2profile_httppost
{
	meta:
		description = "Detects possible C2 malleable fiesta2.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Accept: */*"
		$headerServer0 = "Server: nginx/1.4.4"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"

	condition:
		all of ($header*)
}

rule possibleC2malleable_formbookprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable formbook.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/list/hx28/config.php" fullword
		$headerClient0 = "Host: www.clicks-track.info"
		$headerClient1 = "Connection: close"
		$headerServer0 = "Server: Apache/2.4.18 (Ubuntu)"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerUserAgent = "Mozilla Firefox/4.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_formbookprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable formbook.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/List/hx28/config.php" fullword
		$headerClient0 = "Host: www.clicks-track.info"
		$headerClient1 = "Connection: close"
		$headerClient2 = "Origin: http://www.clicks-track.info"
		$headerClient3 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient4 = "Accept: */*"
		$headerClient5 = "Accept-Language: en-US"
		$headerServer0 = "Server: Apache/2.4.18 (Ubuntu)"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerUserAgent = "Mozilla Firefox/4.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_formbookprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable formbook.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/list/HX28/config.php" fullword
		$uri1 = "/list/hx28/Config.php" fullword
		$headerClient0 = "Host: www.clicks-track.info"
		$headerClient1 = "Connection: close"
		$headerServer0 = "Connection: close"
		$headerServer1 = "Cache-Control: no-cache';"
		$headerServer2 = "Content-Type: application/x-www-form-urlencoded"
		$headerServer3 = "Accept: */*"
		$headerServer4 = "Accept-Language: en-US"
		$headerServer5 = "Accept-Encoding: gzip, deflate"
		$headerUserAgent = "Mozilla Firefox/4.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gandcrabprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable gandcrab.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Host: ransomware.bit"
		$headerClient1 = "Cache-Control: no-cache"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server:  "
		$headerServer1 = "Cache-Control: private"
		$headerServer2 = "Content-Type: text/html"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		all of ($header*)
}

rule possibleC2malleable_gandcrabprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable gandcrab.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/feascui" fullword
		$headerClient0 = "Host: ransomware.bit"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Cache-Control: no-cache"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gandcrabprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable gandcrab.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/da.exe" fullword
		$uri1 = "/DA.exe" fullword
		$headerClient0 = "Host: 185.189.58.222"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache/2.2.15 (CentOS)"
		$headerServer1 = "ETag: 1807d1-49808-5697d14752010"
		$headerServer2 = "Accept-Ranges: bytes"
		$headerServer3 = "Connection: close"
		$headerServer4 = "Content-Type: application/octet-stream"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_globeimposterprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable globeimposter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/JHGcd476334" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Encoding: gzip, deflate"
		$headerClient2 = "Host: awholeblueworld.com"
		$headerClient3 = "Connection: Keep-Alive"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/plain"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "X-Powered-By: PleskLin"
		$headerServer5 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla Firefox/4.0(compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0;SLC2; .NET CLD 3.5.30729; Media Center PC 6.0;)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_globeimposterprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable globeimposter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/count.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Encoding: gzip, deflate"
		$headerClient2 = "Host: awholeblueworld.com"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/plain"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "X-Powered-By: PleskLin"
		$headerServer5 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla Firefox/4.0(compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0;SLC2; .NET CLD 3.5.30729; Media Center PC 6.0;)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_globeimposterprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable globeimposter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/JHGCd476334" fullword
		$uri1 = "/JHGcD476334" fullword
		$headerClient0 = "Host: awholeblueworld"
		$headerClient1 = "Connection: keep-alive"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/plain"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "X-Powered-By: PleskLin"
		$headerServer5 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla Firefox/4.0(compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0;SLC2; .NET CLD 3.5.30729; Media Center PC 6.0;)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gmailprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable gmail.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/_/scs/mail-static/_/js/" fullword
		$headerClient0 = "Cookie"
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient2 = "Accept-Language: en-US,en;q=0.5"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "DNT: 1"
		$headerServer0 = "X-Content-Type-Options: nosniff"
		$headerServer1 = "X-Frame-Options: SAMEORIGIN"
		$headerServer2 = "Cache-Control: public, max-age=31536000"
		$headerServer3 = "X-XSS-Protection: 1; mode=block"
		$headerServer4 = "Server: GSE"
		$headerServer5 = "Alternate-Protocol: 443:quic,p=1"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gmailprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable gmail.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/mail/u/0/" fullword
		$headerClient0 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$headerClient1 = "Cookie"
		$headerServer0 = "X-Content-Type-Options: nosniff"
		$headerServer1 = "X-Frame-Options: SAMEORIGIN"
		$headerServer2 = "Cache-Control: no-cache, no-store, max-age=0, must-revalidate"
		$headerServer3 = "X-XSS-Protection: 1; mode=block"
		$headerServer4 = "Server: GSE"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_googledrive_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable googledrive_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/viewerng/meta" fullword
		$headerClient0 = "Accept: text/html,application/xml;*/*;"
		$headerClient1 = "Accept-Encoding: gzip, deflate"
		$headerClient2 = "Host: drive.google.com"
		$headerClient3 = "Cookie: SID=KsY0f3fxIeBLQRn2wHMhgJvTkFbWZIEqNyABgX_nveBtm9LeEmsHn6I9OmYzpw;"
		$headerServer0 = "Content-Type: application/json; charset=utf-8"
		$headerServer1 = "Cache-Control: no-cache, no-store, max-age=0, must-revalidate"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "X-Content-Type-Options: nosniff"
		$headerServer4 = "X-Frame-Options: SAMEORIGIN"
		$headerServer5 = "X-XSS-Protection: 1; mode=block"
		$headerServer6 = "Server: GSE"
		$headerServer7 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_googledrive_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable googledrive_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/viewersng/meta" fullword
		$headerClient0 = "Accept: text/html,application/xml;*/*;"
		$headerClient1 = "Accept-Encoding: gzip, deflate"
		$headerClient2 = "Host: drive.google.com"
		$headerClient3 = "Cookie: SID=KsY0f3fxIeBLQRn2wHMhgJvTkFbWZIEqNyABgX_nveBtm9LeEmsHn6I9OmYzpw;"
		$headerServer0 = "Content-Type: application/json; charset=utf-8"
		$headerServer1 = "Cache-Control: no-cache, no-store, max-age=0, must-revalidate"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "X-Content-Type-Options: nosniff"
		$headerServer4 = "X-Frame-Options: SAMEORIGIN"
		$headerServer5 = "X-XSS-Protection: 1; mode=block"
		$headerServer6 = "Server: GSE"
		$headerServer7 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gotomeetingprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable gotomeeting.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/functionalStatus" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gotomeetingprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable gotomeeting.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/rest/2/meetings" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en"
		$headerClient2 = "Connection: close'     "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_gotomeetingprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable gotomeeting.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Meeting/32251817/" fullword
		$uri1 = "/Meeting/32251816/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_hancitorprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable hancitor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/mlu/forum.php" fullword
		$headerClient0 = "Host: arrepsinrab.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Encoding: identity, *;q=0"
		$headerClient3 = "Accept-Language: en-US"
		$headerClient4 = "Content-Type: application/octet-stream"
		$headerClient5 = "Connection: close"
		$headerClient6 = "Content-Encoding: binary"
		$headerClient7 = "Cookie"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Keep-Alive: timeout=2, max=100"
		$headerServer3 = "Connection: close"
		$headerServer4 = "X-Powered-By: PHP/5.4.45"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_hancitorprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable hancitor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ls5/forum.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Host: gedidnundno.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerClient4 = "GUID"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Transfer-Encoding: chunked"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "X-Powered-By: PHP/5.4.45"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_hancitorprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable hancitor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/lS5/forum.php" fullword
		$uri1 = "/ls5/Forum.php" fullword
		$headerClient0 = "Accept: text/html, application/xhtml+xml, */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Host: acamonitoringltd.ca"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: application/msword;"
		$headerServer2 = "Keep-Alive: timeout=2, max=100"
		$headerServer3 = "Connection: Keep-Alive"
		$headerServer4 = "X-Powered-By: PHP/5.3.3"
		$headerServer5 = "Content-Disposition: attachment; filename=fax_286509.doc"
		$headerServer6 = "Pragma: private"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_havexprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable havex.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/include/template/isx.php" fullword
		$uri1 = "/wp06/wp-includes/po.php" fullword
		$uri2 = "/wp08/wp-includes/dtcla.php" fullword
		$headerClient0 = "Referer: http://www.google.com"
		$headerClient1 = "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
		$headerClient2 = "Accept-Language: en-us,en;q=0.5"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: Apache/2.2.26 (Unix)"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Cache-Control: no-cache"
		$headerServer3 = "Content-Type: text/html"
		$headerServer4 = "Keep-Alive: timeout=3, max=100"
		$headerUserAgent = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2) Java/1.5.0_08"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_havexprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable havex.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/modules/mod_search.php" fullword
		$uri1 = "/blog/wp-includes/pomo/src.php" fullword
		$uri2 = "/includes/phpmailer/class.pop3.php" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerServer0 = "Server: Apache/2.2.26 (Unix)"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Cache-Control: no-cache"
		$headerServer3 = "Content-Type: text/html"
		$headerServer4 = "Keep-Alive: timeout=3, max=100"
		$headerUserAgent = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2) Java/1.5.0_08"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_iheartradioprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable iheartradio.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/live/hit-nation-4222/" fullword
		$headerClient0 = "Host: www.iheart.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Connection: close"
		$headerClient4 = "Cookie"
		$headerServer0 = "Content-Type: text/html; charset=utf-8"
		$headerServer1 = "Edge-Control: cache-maxage=3600"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "X-Powered-By: Express"
		$headerServer4 = "Access-Control-Allow-Origin: *"
		$headerServer5 = "Accept-Ranges: bytes"
		$headerServer6 = "Via: 1.1 varnish"
		$headerServer7 = "Age: 315"
		$headerServer8 = "Connection: close"
		$headerServer9 = "X-Served-By: cache-dfw1822-DFW"
		$headerServer10 = "X-Cache: HIT"
		$headerServer11 = "X-Cache-Hits: 1"
		$headerServer12 = "X-Timer: S1499866924.089752,VS0,VE1"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_iheartradioprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable iheartradio.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Live/hit-nation-4222/" fullword
		$headerClient0 = "Host: www.iheart.com"
		$headerClient1 = "Accept: */*'     "
		$headerClient2 = "Cookie"
		$headerServer0 = "Content-Type: text/html; charset=utf-8"
		$headerServer1 = "Edge-Control: cache-maxage=3600"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "X-Powered-By: Express"
		$headerServer4 = "Access-Control-Allow-Origin: *"
		$headerServer5 = "Accept-Ranges: bytes"
		$headerServer6 = "Via: 1.1 varnish"
		$headerServer7 = "Age: 315"
		$headerServer8 = "Connection: close"
		$headerServer9 = "X-Served-By: cache-dfw1822-DFW"
		$headerServer10 = "X-Cache: HIT"
		$headerServer11 = "X-Cache-Hits: 1"
		$headerServer12 = "X-Timer: S1499866924.089752,VS0,VE1"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_iheartradioprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable iheartradio.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Console" fullword
		$uri1 = "/console" fullword
		$headerServer0 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jaffprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable jaff.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/af/fgJds2U" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US' "
		$headerClient2 = "Host: minnessotaswordfishh.com"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Connection: Keep-Alive"
		$headerClient5 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Etag: 15caf86-3b000-550323b001000"
		$headerServer2 = "Connection: Keep-Alive"
		$headerServer3 = "Accept-Ranges: bytes"
		$headerUserAgent = "Mozilla/5.2 (Windows NT 6.2; rv:50.2) Gecko/20200103 Firefox/50.2"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jaffprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable jaff.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/a5/" fullword
		$headerClient0 = "Host: maximusstafastoriesticks.info"
		$headerClient1 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/plain; charset=utf-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Etag: W/'7-rM9AyJuqT6iOan/xHh+AW+7K/T*"
		$headerUserAgent = "Mozilla/5.2 (Windows NT 6.2; rv:50.2) Gecko/20200103 Firefox/50.2"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jasperloaderprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable jasperloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/loadercrypt_823EF8A810513A4071485C36DDAD4CC3.php" fullword
		$headerClient0 = "Host: cdn.zaczvk.pl"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx/1.14.2"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "X-Powered-By: PHP/5.4.16"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jasperloaderprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable jasperloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Host: space.bajamelide.ch"
		$headerClient1 = "Connection: Keep-Alive'     "
		$headerServer0 = "Server: nginx/1.14.2"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Content-Length: 89"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "X-Powered-By: PHP/5.4.16"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		all of ($header*)
}

rule possibleC2malleable_jasperloaderprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jasperloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/501" fullword
		$uri1 = "/502" fullword
		$headerClient0 = "Host: cloud.diminishedvaluecalifornia.com"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache/2.2.15 (CentOS)"
		$headerServer1 = "Last-Modified: Tue, 22 Jan 2019 16:31:28 GMT"
		$headerServer2 = "ETag: 9f688-4-5800e82560818"
		$headerServer3 = "Accept-Ranges: bytes"
		$headerServer4 = "Content-Length: 4"
		$headerServer5 = "Connection: close"
		$headerServer6 = "Content-Type: text/html; charset=UTF-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2311profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.11.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2311profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.11.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2311profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.11.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Host: code.jquery.com"
		$headerClient3 = "Referer: http://code.jquery.com/"
		$headerClient4 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2312profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.12.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2312profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.12.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2312profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.12.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Host: code.jquery.com"
		$headerClient3 = "Referer: http://code.jquery.com/"
		$headerClient4 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2313profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.13.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2313profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.13.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2313profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.13.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Host: code.jquery.com"
		$headerClient3 = "Referer: http://code.jquery.com/"
		$headerClient4 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2314profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.14.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2314profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.14.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Host: code.jquery.com"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc2314profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.3.14.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Host: code.jquery.com"
		$headerClient3 = "Referer: http://code.jquery.com/"
		$headerClient4 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc240profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.0.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc240profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.0.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc240profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.0.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc242profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.2.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc242profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.2.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc242profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.2.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc243profile_httpget
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.3.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc243profile_httppost
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.3.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.2.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Referer: http://code.jquery.com/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_jqueryc243profile_httpstager
{
	meta:
		description = "Detects possible C2 malleable jquery-c2.4.3.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jquery-3.3.1.slim.min.js" fullword
		$uri1 = "/jquery-3.3.2.slim.min.js" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Referer: http://code.jquery.com/"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerServer0 = "Server: NetDNA-cache/2.2"
		$headerServer1 = "Cache-Control: max-age=0, no-cache"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "Content-Type: application/javascript; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_kronosprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable kronos.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/lampi/upload/38bacf4f.exe" fullword
		$headerClient0 = "Host: hjbkjbhkjhbkjhl.info"
		$headerClient1 = "Cookie"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "Connection: close"
		$headerServer3 = "ETag: 2ca0669-6d600-557bba73d8218"
		$headerServer4 = "Accept-Ranges: bytes"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_kronosprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable kronos.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/lampi/connect.php" fullword
		$headerClient0 = "Host: hjbkjbhkjhbkjhl.info"
		$headerClient1 = "Cache-Control: no-cache'     "
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html; charset=windows-1251"
		$headerServer2 = "X-Powered-By: PHP/5.3.3"
		$headerServer3 = "Cache-Control: no-store, non-cache, must-revalidate, post-check=0, pre-check=0"
		$headerServer4 = "Pragma: non-cache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_kronosprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable kronos.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/lampi/Connect.php" fullword
		$uri1 = "/Lampi/connect.php" fullword
		$headerClient0 = "Host: hjbkjbhkjhbkjhl.info"
		$headerClient1 = "Cache-Control: no-cache"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html; charset=windows-1251"
		$headerServer2 = "X-Powered-By: PHP/5.3.3"
		$headerServer3 = "Cache-Control: no-store, non-cache, must-revalidate, post-check=0, pre-check=0"
		$headerServer4 = "Pragma: non-cache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_magnitudeprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable magnitude.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/themes/index.php" fullword
		$headerClient0 = "Accept: image/jpeg, application/*"
		$headerClient1 = "Referer: http://www.bankofbotswana.bw/"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Host: wilfredcostume.bamoon.com"
		$headerServer0 = "Server: Apache/2.2.17 (Ubuntu)"
		$headerServer1 = "X-Powered-By: PHP/5.3.5-1ubuntu7.8"
		$headerServer2 = "Content-Encoding: gzip"
		$headerServer3 = "Content-Type: text/html"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_magnitudeprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable magnitude.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/work/1.php" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US;q=0.5,en;q=0.3"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Content-Type: application/octet-stream"
		$headerServer0 = "Server: Apache/2.2.17 (Ubuntu)"
		$headerServer1 = "X-Powered-By: PHP/5.3.5-1ubuntu7.8"
		$headerServer2 = "Content-Encoding: gzip"
		$headerServer3 = "Content-Type: text/html"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mayoclinicprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable mayoclinic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/discussion/mayo-clinic-radio-als/" fullword
		$uri1 = "/discussion/" fullword
		$uri2 = "/hubcap/mayo-clinic-radio-full-shows/" fullword
		$uri3 = "/category/research-2/" fullword
		$headerClient0 = "Host: www.mayomedical.com' "
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' "
		$headerClient2 = "Accept-Language: en-US,en;q=0.5' "
		$headerClient3 = "Connection: close' "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mayoclinicprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable mayoclinic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/archive/" fullword
		$uri1 = "/bloglist/" fullword
		$uri2 = "/secondary-archive/" fullword
		$headerClient0 = "Host: www.mayomedical.com' "
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' "
		$headerClient2 = "Accept-Language: en-US,en;q=0.5' "
		$headerClient3 = "Connection: close'     "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mayoclinicprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable mayoclinic.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/tag/" fullword
		$uri1 = "/Category/" fullword
		$headerClient0 = "Host: www.mayomedical.com' "
		$headerClient1 = "Accept: */*' "
		$headerClient2 = "Accept-Language: en-US' "
		$headerClient3 = "Connection: close' "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_meterpreterprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable meterpreter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ucD" fullword
		$headerClient0 = "Cache-Control: no-cache"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Pragma: no-cache"
		$headerServer0 = "Content-Type: application/octet-stream"
		$headerServer1 = "Connection: Keep-Alive"
		$headerServer2 = "Server: Apache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_meterpreterprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable meterpreter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ucW" fullword
		$headerClient0 = "Cache-Control: no-cache"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Pragma: no-cache"
		$headerServer0 = "Content-Type: application/octet-stream"
		$headerServer1 = "Connection: Keep-Alive"
		$headerServer2 = "Server: Apache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_microsoftupdate_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable microsoftupdate_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/c/msdownload/update/others/2016/12/29136388_" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: download.windowsupdate.com"
		$headerServer0 = "Content-Type: application/vnd.ms-cab-compressed"
		$headerServer1 = "Server: Microsoft-IIS/8.5"
		$headerServer2 = "MSRegion: N. America"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "X-Powered-By: ASP.NET"
		$headerUserAgent = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_microsoftupdate_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable microsoftupdate_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/c/msdownload/update/others/2016/12/3215234_" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host"
		$headerServer0 = "Content-Type: application/vnd.ms-cab-compressed"
		$headerServer1 = "Server: Microsoft-IIS/8.5"
		$headerServer2 = "MSRegion: N. America"
		$headerServer3 = "Connection: keep-alive"
		$headerServer4 = "X-Powered-By: ASP.NET"
		$headerUserAgent = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mscrlprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable mscrl.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/pki/mscorp/cps/default.htm" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*,q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Connection: close"
		$headerClient3 = "Cookie"
		$headerServer0 = "Content-Type: text/html"
		$headerServer1 = "x-ms-version: 2009-09-19"
		$headerServer2 = "x-ms-lease-status: unlocked"
		$headerServer3 = "x-ms-blob-type: BlockBlob"
		$headerServer4 = "Vary: Accept-Encoding"
		$headerServer5 = "Connection: close"
		$headerServer6 = "TLS_version: tls1.2"
		$headerServer7 = "Strict-Transport-Security: max-age=31536000"
		$headerServer8 = "X-RTag: RT"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mscrlprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable mscrl.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/pki/mscorp/crl/msitwww1.crl" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en"
		$headerClient2 = "Connection: close"
		$headerClient3 = "x-ms-request-id"
		$headerClient4 = "Content-MD5"
		$headerServer0 = "Age: 1919"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "x-ms-blob-type: BlockBlob"
		$headerServer3 = "x-ms-lease-status: unlocked"
		$headerServer4 = "x-ms-version: 572"
		$headerServer5 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_mscrlprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable mscrl.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/pki/mscorp/crl/Msitwww1.crl" fullword
		$uri1 = "/pki/mscorp/CRL/msitwww1.crl" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en"
		$headerClient2 = "Connection: close"
		$headerServer0 = "Content-Type: text/html;charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: ZOOM"
		$headerServer3 = "X-Robots-Tag: noindex, nofollow"
		$headerServer4 = "X-Content-Type-Options: nosniff"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_msnbcvideo_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable msnbcvideo_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/z/msnbc2_live01@9615/manifest.f4m" fullword
		$headerClient0 = "Host: msnbc2prod-lh.akamaihd.net"
		$headerClient1 = "X-Requested-With: ShockwaveFlash/24.0.0.186"
		$headerClient2 = "Referer: http://player.theplatform.com/p/7wvmTC/NBCOnAirProdPlayer/embed/select?s=msnbc"
		$headerServer0 = "Server: AkamaiGHost"
		$headerServer1 = "Mime-Version: 1.0"
		$headerServer2 = "Content-Type: video/abst"
		$headerServer3 = "Cache-Control: max-age=0, no-cache"
		$headerServer4 = "Pragma: no-cache"
		$headerServer5 = "Connection: keep-alive"
		$headerServer6 = "Set-Cookie: _alid_=RKs7UfhDqLr37whMpHIwBg==; path=/z/msnbc2_live01@9615/; domain=msnbc2prod-lh.akamaihd.net"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_msnbcvideo_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable msnbcvideo_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/z/msnbc2_live01@6915/manifest.f4m" fullword
		$headerClient0 = "Host: msnbc2prod-lh.akamaihd.net"
		$headerClient1 = "X-Requested-With: ShockwaveFlash/24.0.0.186"
		$headerClient2 = "Referer    "
		$headerServer0 = "Server: AkamaiGHost"
		$headerServer1 = "Mime-Version: 1.0"
		$headerServer2 = "Content-Type: video/abst"
		$headerServer3 = "Cache-Control: max-age=0, no-cache"
		$headerServer4 = "Pragma: no-cache"
		$headerServer5 = "Connection: keep-alive"
		$headerServer6 = "Set-Cookie: _alid_=RKs7UfhDqLr37whMpHIwBg==; path=/z/msnbc2_live01@6915/; domain=msnbc2prod-lh.akamaihd.net"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_msu_eduprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable msu_edu.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/siteindex/a/" fullword
		$uri1 = "/siteindex/b/" fullword
		$uri2 = "/siteindex/c/" fullword
		$headerClient0 = "Host: search.missouristate.edu"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Vary: User-Agent"
		$headerServer3 = "Server: Microsoft-IIS/8.5"
		$headerServer4 = "BackendServer: Handle"
		$headerServer5 = "X-UA-Compatible: IE=edge"
		$headerServer6 = "Connection: close"
		$headerServer7 = "Set-Cookie: WWW-SERVERID=handle; path=/"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_msu_eduprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable msu_edu.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/getsearchresults" fullword
		$headerClient0 = "Connection: close"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US'   "
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: application/json; charset=utf-8"
		$headerServer2 = "Vary: User-Agent,AcceptEncoding"
		$headerServer3 = "Server: Microsoft-IIS/8.5"
		$headerServer4 = "BackendServer: Handle"
		$headerServer5 = "X-UA-Compatible: IE=edge"
		$headerServer6 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_msu_eduprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable msu_edu.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Events" fullword
		$uri1 = "/events" fullword
		$headerClient0 = "Host: search.missouristate.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: private"
		$headerServer2 = "Vary: User-Agent"
		$headerServer3 = "Server: Microsoft-IIS/8.5"
		$headerServer4 = "BackendServer: Handle"
		$headerServer5 = "X-UA-Compatible: IE=edge"
		$headerServer6 = "Connection: close"
		$headerServer7 = "Set-Cookie: WWW-SERVERID=handle; path=/'; "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ocspprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable ocsp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/oscp/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: ocsp.verisign.com"
		$headerServer0 = "Content-Type: application/ocsp-response"
		$headerServer1 = "content-transfer-encoding: binary"
		$headerServer2 = "Cache-Control: max-age=547738, public, no-transform, must-revalidate"
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Microsoft-CryptoAPI/6.1"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ocspprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable ocsp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/oscp/a/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: ocsp.verisign.com"
		$headerServer0 = "Content-Type: application/ocsp-response"
		$headerServer1 = "content-transfer-encoding: binary"
		$headerServer2 = "Cache-Control: max-age=547738, public, no-transform, must-revalidate"
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Microsoft-CryptoAPI/6.1"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_office365_calendarprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable office365_calendar.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/owa/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Cookie: MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;ClientId=1C0F6C5D910F9;MSPAuth=3EkAjDKjI;xid=730bf7;wla42=ZG0yMzA2KjEs"
		$headerServer0 = "Cache-Control: no-cache"
		$headerServer1 = "Pragma: no-cache"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerServer3 = "Server: Microsoft-IIS/10.0"
		$headerServer4 = "request-id: 6cfcf35d-0680-4853-98c4-b16723708fc9"
		$headerServer5 = "X-CalculatedBETarget: BY2PR06MB549.namprd06.prod.outlook.com"
		$headerServer6 = "X-Content-Type-Options: nosniff"
		$headerServer7 = "X-OWA-Version: 15.1.1240.20"
		$headerServer8 = "X-OWA-OWSVersion: V2017_06_15"
		$headerServer9 = "X-OWA-MinimumSupportedOWSVersion: V2_6"
		$headerServer10 = "X-Frame-Options: SAMEORIGIN"
		$headerServer11 = "X-DiagInfo: BY2PR06MB549"
		$headerServer12 = "X-UA-Compatible: IE=EmulateIE7"
		$headerServer13 = "X-Powered-By: ASP.NET"
		$headerServer14 = "X-FEServer: CY4PR02CA0010"
		$headerServer15 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_office365_calendarprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable office365_calendar.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/OWA/" fullword
		$headerClient0 = "Accept: */*'     "
		$headerClient1 = "Cookie"
		$headerServer0 = "Cache-Control: no-cache"
		$headerServer1 = "Pragma: no-cache"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerServer3 = "Server: Microsoft-IIS/10.0"
		$headerServer4 = "request-id: 6cfcf35d-0680-4853-98c4-b16723708fc9"
		$headerServer5 = "X-CalculatedBETarget: BY2PR06MB549.namprd06.prod.outlook.com"
		$headerServer6 = "X-Content-Type-Options: nosniff"
		$headerServer7 = "X-OWA-Version: 15.1.1240.20"
		$headerServer8 = "X-OWA-OWSVersion: V2017_06_15"
		$headerServer9 = "X-OWA-MinimumSupportedOWSVersion: V2_6"
		$headerServer10 = "X-Frame-Options: SAMEORIGIN"
		$headerServer11 = "X-DiagInfo: BY2PR06MB549"
		$headerServer12 = "X-UA-Compatible: IE=EmulateIE7"
		$headerServer13 = "X-Powered-By: ASP.NET"
		$headerServer14 = "X-FEServer: CY4PR02CA0010"
		$headerServer15 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_office365_calendarprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable office365_calendar.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/rpc" fullword
		$uri1 = "/Rpc" fullword
		$headerClient0 = "Accept: */*"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_onedrive_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable onedrive_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/preload" fullword
		$headerClient0 = "Host: onedrive.live.com"
		$headerClient1 = "Accept: text/html,application/xml;*/*;"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Cache-Control: no-cache, no-store"
		$headerServer1 = "Pragma: no-cache"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerServer3 = "Expires: -1"
		$headerServer4 = "Vary: Accept-Encoding"
		$headerServer5 = "Server: Microsoft-IIS/8.5"
		$headerServer6 = "Set-Cookie: E=P:We/01nw8bIg=:oIbA04j2Itig4t8cWKNKrDaG/ZDZuMnyxXC+BkkNivU=:F; domain=.live.com; path=/"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_onedrive_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable onedrive_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/sa" fullword
		$headerClient0 = "Host: onedrive.live.com"
		$headerClient1 = "Accept: text/html,application/xml;*/*;"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerClient4 = "Referer"
		$headerServer0 = "Cache-Control: no-cache, no-store"
		$headerServer1 = "Pragma: no-cache"
		$headerServer2 = "Content-Type: text/html; charset=utf-8"
		$headerServer3 = "Expires: -1"
		$headerServer4 = "Vary: Accept-Encoding"
		$headerServer5 = "Server: Microsoft-IIS/8.5"
		$headerServer6 = "Set-Cookie: E=P:We/01nw8bIg=:oItIbA04j2rDig4t8cWKNKaG/ZDZuMnyxXC+BkkNivU=:F; domain=.live.com; path=/"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_oscpprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable oscp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/oscp/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: ocsp.verisign.com"
		$headerServer0 = "Content-Type: application/ocsp-response"
		$headerServer1 = "content-transfer-encoding: binary"
		$headerServer2 = "Cache-Control: max-age=547738, public, no-transform, must-revalidate"
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Microsoft-CryptoAPI/6.1"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_oscpprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable oscp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/oscp/a/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: ocsp.verisign.com"
		$headerServer0 = "Content-Type: application/ocsp-response"
		$headerServer1 = "content-transfer-encoding: binary"
		$headerServer2 = "Cache-Control: max-age=547738, public, no-transform, must-revalidate"
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Microsoft-CryptoAPI/6.1"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_pandoraprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable pandora.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/access/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "GetContentFeatures.DLNA.ORG: 1"
		$headerClient2 = "Host: audio-sv5-t1-3.pandora.com"
		$headerClient3 = "Cookie:  __utma=210077622.1732439995.1433201462.1403204372.1385202493.2;"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "Cache-Control: no-cache, no-store, must-revalidate, max-age=-1"
		$headerServer2 = "Pragma: no-cache, no-store"
		$headerServer3 = "Connection: close"
		$headerServer4 = "Content-Type: audio/mp4"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_pandoraprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable pandora.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/radio/xmlrpc/v35" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: text/xml"
		$headerClient2 = "X-Requested-With: XMLHttpRequest"
		$headerClient3 = "Host: www.pandora.com"
		$headerServer0 = "Content-Type: text/xml"
		$headerServer1 = "Cache-Control: no-cache, no-store, no-transform, must-revalidate, max-age=0"
		$headerServer2 = "Expires: -1"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_pitty_tigerprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable pitty_tiger.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/FC001/JOHN" fullword
		$headerClient0 = "Host: newb02.skypetm.com.tw"
		$headerClient1 = "Connection: Keel-Alive"
		$headerServer0 = "Connection: Keel-Alive"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Server: IIS5.0"
		$headerUserAgent = "Microsoft Internet Explorer"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_pitty_tigerprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable pitty_tiger.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/FC002/JOHN-" fullword
		$headerClient0 = "Host: newb02.skypetm.com.tw"
		$headerClient1 = "Connection: Keel-Alive"
		$headerServer0 = "Connection: Keel-Alive"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Server: IIS5.0"
		$headerUserAgent = "Microsoft Internet Explorer"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_POSeidonprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable POSeidon.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Baked/viewtopic.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Host: retjohnuithun.com"
		$headerClient3 = "Cache-Control: no-cache'	"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "X-Powered-By: PHP/5.4.38"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_POSeidonprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable POSeidon.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/baked/viewtopic.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Host: retjohnuithun.com"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "X-Powered-By: PHP/5.4.38"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_POSeidonprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable POSeidon.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ldl01/viewtopic.php" fullword
		$uri1 = "/Ldl01/viewtopic.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient2 = "Host: retjohnuithun.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "X-Powered-By: PHP/5.4.38"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; Media Center PC 6.0)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_powrunerprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable powruner.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/update_wapp2.aspx" fullword
		$headerClient0 = "Host: 46.105.221.247"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: text/plain; charset=utf-8';"
		$headerServer2 = "Server: Microsoft-IIS/8.5"
		$headerServer3 = "X-AspNet-Version: 4.0.30319"
		$headerServer4 = "X-Powered-By: ASP.NET"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_powrunerprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable powruner.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/update_Wapp2.aspx" fullword
		$headerClient0 = "Host: 46.105.221.247"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cookie"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: text/plain; charset=utf-8';"
		$headerServer2 = "Server: Microsoft-IIS/8.5"
		$headerServer3 = "X-AspNet-Version: 4.0.30319"
		$headerServer4 = "X-Powered-By: ASP.NET"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_powrunerprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable powruner.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Update_wapp2.aspx" fullword
		$uri1 = "/update_wapP2.aspx" fullword
		$headerClient0 = "Host: 46.105.221.247"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: text/plain; charset=utf-8';"
		$headerServer2 = "Server: Microsoft-IIS/8.5"
		$headerServer3 = "X-AspNet-Version: 4.0.30319"
		$headerServer4 = "X-Powered-By: ASP.NET"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_putterprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable putter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/MicrosoftUpdate/ShellEx/KB242742/default.aspx" fullword
		$headerClient0 = "Accept: */*, ..., ......, .' "
		$headerServer0 = "Content-Type: application/octet-stream"
		$headerUserAgent = "Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_putterprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable putter.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/MicrosoftUpdate/GetUpdate/KB" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerServer0 = "Content-Type: text/html"
		$headerUserAgent = "Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_qakbotprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable qakbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/TealeafTarget.php" fullword
		$headerClient0 = "Connection: Keep-Alive"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-us"
		$headerClient3 = "Host: projects.montgomerytech.com"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: nginx/1.12.0"
		$headerServer1 = "Date: Thu, 04 May 2017 19:01:45 GMT"
		$headerServer2 = "Content-Type: image/jpeg; charset=ISO-8859-1"
		$headerServer3 = "Content-Length: 925776';       "
		$headerServer4 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_qakbotprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable qakbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/TeaLeafTarget.php" fullword
		$headerClient0 = "Connection: Keep-Alive"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-us'        "
		$headerClient3 = "Host: projects.montgomerytech.com"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: nginx/1.12.0"
		$headerServer1 = "Date: Thu, 04 May 2017 19:01:45 GMT"
		$headerServer2 = "Content-Type: image/jpeg; charset=ISO-8859-1"
		$headerServer3 = "Content-Length: 925776';       "
		$headerServer4 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_quantloaderprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable quantloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/q2/index.php" fullword
		$headerClient0 = "Host: wassronledorhad.in"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=windows-1251"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_quantloaderprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable quantloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Q2/index.php" fullword
		$headerClient0 = "Host: wassronledorhad.in"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=windows-1251"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_quantloaderprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable quantloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/q2/Index.php" fullword
		$uri1 = "/Q2/Index.php" fullword
		$headerClient0 = "Host: wassronledorhad.in"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=windows-1251"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ramnitprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable ramnit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/redirect" fullword
		$headerClient0 = "Accept: text/html, application/xhtml+xml, */*"
		$headerClient1 = "Accept-Language: en-US'	"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Host: redirect.turself-josented.com"
		$headerClient4 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html;charset=UTF-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Cache-Control: no-store, no-cache, pre-check=0, post-check=0"
		$headerServer4 = "Expires: Thu, 01 Jan 1970 00:00:00 GMT"
		$headerServer5 = "Pragma: no-cache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ramnitprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable ramnit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Redirect.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Referer: http://........../redirect.php?acsc=93042904"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Host: xn--b1aanbboc3ad8jee4bff.xn--p1ai"
		$headerClient4 = "Referer"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html, charset=UTF-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "X-Powered-By: PHP/5.6.30"
		$headerServer5 = "Cache-Control: no-store, no-cache, must-revalidate, max-age=0"
		$headerServer6 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ramnitprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable ramnit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Jump/next.php" fullword
		$uri1 = "/jump/Next.php" fullword
		$headerClient0 = "Accept: text/html, application/xhtml+xml, */*"
		$headerClient1 = "Referer: http://buzzadnetwork.com/jump/next.php?r=1566861&sub1="
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Accept-Encoding: gzip, deflate"
		$headerClient4 = "Host: www.buzzadnetwork.com"
		$headerClient5 = "Connection: Keep-Alive"
		$headerServer0 = "Server: openresty"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Keep-Alive: timeout=2, max=100"
		$headerServer3 = "Connection: Keep-Alive"
		$headerServer4 = "Location: http://xn--b1aanbboc3ad8jee4bff.xn--p1ai/redirect.php?acsc=93042904"
		$headerServer5 = "Referrer-Policy: no-referrer"
		$headerServer6 = "Vary: Accept-Encoding"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_randomizedprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable randomized.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/zC" fullword
		$headerServer0 = "Content-Type: text/plain"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_randomizedprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable randomized.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/dE" fullword
		$headerClient0 = "Content-Type: application/x-www-form-urlencoded"
		$headerServer0 = "Content-Type: text/plain"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ratankbaprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable ratankba.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jscroll/board/list.jpg" fullword
		$uri1 = "/design/dfbox/list.jpg" fullword
		$uri2 = "/design/img/list.jpg" fullword
		$headerClient0 = "Host: www.eye-watch.in"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Cookie: 0449651003fe48-Nff0eb7"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ratankbaprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable ratankba.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/jscroll/board/List.jpg" fullword
		$uri1 = "/design/dfbox/List.jpg" fullword
		$uri2 = "/design/img/List.jpg" fullword
		$headerClient0 = "Host: www.eye-watch.in"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Cookie"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Server: nginx/1.4.6 (Ubuntu)"
		$headerServer3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_redditprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable reddit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/r/webdev/comments/95ltyr" fullword
		$headerClient0 = "Host: www.reddit.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Connection: close"
		$headerClient4 = "Cookie"
		$headerServer0 = "Cache-control: private, s-maxage=0, max-age=0, must-revalidate"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_redditprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable reddit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/r/webdev/comments/95lyr/slow_loading_of_google" fullword
		$headerClient0 = "Host: www.reddit.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Cookie"
		$headerServer0 = "Cache-control: private, s-maxage=0, max-age=0, must-revalidate"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_redditprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable reddit.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/r/Webdev" fullword
		$uri1 = "/r/WebDev" fullword
		$headerClient0 = "Host: www.reddit.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-control: private, s-maxage=0, max-age=0, must-revalidate"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_referenceprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable reference.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/api/v1/Updates" fullword
		$headerClient0 = "Accept-Encoding: deflate, gzip;q=1.0, *;q=0.5"
		$headerClient1 = "Cookie"
		$headerServer0 = "Content-Type: application/octet-stream"
		$headerServer1 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_referenceprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable reference.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/api/v1/Telemetry/Id/" fullword
		$headerClient0 = "Content-Type: application/json"
		$headerClient1 = "Accept-Encoding: deflate, gzip;q=1.0, *;q=0.5"
		$headerServer0 = "Content-Type: application/octet-stream"
		$headerServer1 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_referenceprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable reference.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/api/v1/GetLicence" fullword
		$uri1 = "/api/v2/GetLicence" fullword
		$headerServer0 = "Content-Type: application/octet-stream';   "
		$headerServer1 = "Content-Encoding: gzip';   "
		$headerUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_rigEKprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable rigEK.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Accept: text/html, */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Host: 176.57.208.59"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx/1.6.2"
		$headerServer1 = "Content-Type: text/html;charset=UTF-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Vary: Accept-Encoding"
		$headerServer4 = "Content-Encoding: gzip"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		all of ($header*)
}

rule possibleC2malleable_rigEKprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable rigEK.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/gate.php" fullword
		$headerClient0 = "Host: doueven.click"
		$headerClient1 = "Connection: close"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Content-Type: image/jpeg"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "Upgrade: h2,h2c"
		$headerServer2 = "Connection: Upgrade, close"
		$headerServer3 = "Content-Type: application/octet-stream"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_rigEKprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable rigEK.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/prink.exe" fullword
		$uri1 = "/Prink.exe" fullword
		$headerClient0 = "Host: 31.31.203.14"
		$headerClient1 = "Accept-Language: en-us"
		$headerClient2 = "Accept: text/html, application/xml, image/png, image/jpeg, image/gif, image/x-xbitmap"
		$headerClient3 = "Accept-Charset: utf-8, utf-16, iso-8859-1"
		$headerClient4 = "Pragma: non-cache"
		$headerClient5 = "Connection: close"
		$headerServer0 = "Server: nginx/1.10.2"
		$headerServer1 = "Content-Type: application/octet-stream"
		$headerServer2 = "Keep-Alive: timeout=2, max=100"
		$headerServer3 = "Connection: close"
		$headerServer4 = "ETag: be339-de000-563c784ba5900"
		$headerServer5 = "Accept-Ranges: bytes"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_rtmpprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable rtmp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/idle/1376547834/1" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cache-Control: no-cache"
		$headerClient3 = "Content-Type: application/x-fcs"
		$headerClient4 = "Cookie"
		$headerServer0 = "Content-Type: application/x-fcs"
		$headerServer1 = "Connection: Keep-Alive"
		$headerServer2 = "Server: FlashCom/3.5.7"
		$headerServer3 = "Cache-Control: no-cache"
		$headerUserAgent = "Shockwave Flash"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_rtmpprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable rtmp.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/send/1376547834/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cache-Control: no-cache"
		$headerClient3 = "Content-Type: application/x-fcs"
		$headerServer0 = "Content-Type: application/x-fcs"
		$headerServer1 = "Connection: Keep-Alive"
		$headerServer2 = "Server: FlashCom/3.5.7"
		$headerServer3 = "Cache-Control: no-cache"
		$headerUserAgent = "Shockwave Flash"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_saefkoprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable saefko.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/love/server.php" fullword
		$headerClient0 = "Host: acpananma.com"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "X-Powered-By: PHP/5.6.36"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "Content-Type: text/html; charset=UTF-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_saefkoprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable saefko.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Love/server.php" fullword
		$headerClient0 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient1 = "Host: acpananma.com"
		$headerClient2 = "Expect: 100-continue"
		$headerClient3 = "Connection: Keep-Alive"
		$headerServer0 = "Host: acpananma.com"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_saefkoprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable saefko.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/clients2.google.com/generate_204" fullword
		$uri1 = "/clients3.google.com/generate_204" fullword
		$headerClient0 = "Host: acpananma.com"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "X-Powered-By: PHP/5.6.36"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "Content-Type: text/html; charset=UTF-8"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_safebrowsingprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable safebrowsing.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/safebrowsing/rd/CltOb12nLW1IbHehcmUtd2hUdmFzEBAY7-0KIOkUDC7h2" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Content-Type: application/vnd.google.safebrowsing-chunk"
		$headerServer1 = "X-Content-Type-Options: nosniff"
		$headerServer2 = "Content-Encoding: gzip"
		$headerServer3 = "X-XSS-Protection: 1; mode=block"
		$headerServer4 = "X-Frame-Options: SAMEORIGIN"
		$headerServer5 = "Cache-Control: public,max-age=172800"
		$headerServer6 = "Age: 1222"
		$headerServer7 = "Alternate-Protocol: 80:quic"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_safebrowsingprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable safebrowsing.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/safebrowsing/rd/CINnu27nLO8hbHdfgmUtc2ihdmFyEAcY4" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Cookie"
		$headerServer0 = "Content-Type: application/vnd.google.safebrowsing-chunk"
		$headerServer1 = "X-Content-Type-Options: nosniff"
		$headerServer2 = "Content-Encoding: gzip"
		$headerServer3 = "X-XSS-Protection: 1; mode=block"
		$headerServer4 = "X-Frame-Options: SAMEORIGIN"
		$headerServer5 = "Cache-Control: public,max-age=172800"
		$headerServer6 = "Age: 1222"
		$headerServer7 = "Alternate-Protocol: 80:quic"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_slackprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable slack.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/messages/C0527B0NM" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Connection: close"
		$headerClient3 = "Cookie"
		$headerServer0 = "Content-Type: text/html; charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: Apache"
		$headerServer3 = "X-XSS-Protection: 0"
		$headerServer4 = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
		$headerServer5 = "Referrer-Policy: no-referrer"
		$headerServer6 = "X-Slack-Backend: h"
		$headerServer7 = "Pragma: no-cache"
		$headerServer8 = "Cache-Control: private, no-cache, no-store, must-revalidate"
		$headerServer9 = "X-Frame-Options: SAMEORIGIN"
		$headerServer10 = "Vary: Accept-Encoding"
		$headerServer11 = "X-Via: haproxy-www-w6k7"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_slackprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable slack.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/api/api.test" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US'     "
		$headerClient2 = "Cookie"
		$headerClient3 = "_ga"
		$headerServer0 = "Content-Type: application/json; charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: Apache"
		$headerServer3 = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
		$headerServer4 = "Referrer-Policy: no-referrer"
		$headerServer5 = "X-Content-Type-Options: nosniff"
		$headerServer6 = "X-Slack-Req-Id: 6319165c-f976-4d0666532"
		$headerServer7 = "X-XSS-Protection: 0"
		$headerServer8 = "X-Slack-Backend: h"
		$headerServer9 = "Vary: Accept-Encoding"
		$headerServer10 = "Access-Control-Allow-Origin: *"
		$headerServer11 = "X-Via: haproxy-www-6g1x"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_slackprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable slack.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/messages/DALBNSf25" fullword
		$uri1 = "/messages/DALBNSF25" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Accept-Encoding: gzip, deflate"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Content-Type: text/html; charset=utf-8';       "
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: Apache"
		$headerServer3 = "X-XSS-Protection: 0"
		$headerServer4 = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
		$headerServer5 = "Referrer-Policy: no-referrer"
		$headerServer6 = "X-Slack-Backend: h"
		$headerServer7 = "Pragma: no-cache"
		$headerServer8 = "Cache-Control: private, no-cache, no-store, must-revalidate"
		$headerServer9 = "X-Frame-Options: SAMEORIGIN"
		$headerServer10 = "Vary: Accept-Encoding"
		$headerServer11 = "X-Via: haproxy-www-suhx"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_sofacyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable sofacy.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/url/544036/cormac.mcr" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8"
		$headerClient1 = "Connection: Close"
		$headerClient2 = "Host: adawareblock.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: Apache/2.2.26 (Unix)"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_sofacyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable sofacy.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/k9/eR3/a/UE/eR.pdf/bKC=xCCmnuXFZ6Chw2ah1oM=" fullword
		$headerClient0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Host: adawareblock.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Server: Apache/2.2.26 (Unix)"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Content-Type: text/html"
		$headerServer3 = "Content-Length: 58"
		$headerServer4 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_stackoverflowprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable stackoverflow.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/questions/32251816/c-sharp-directives-compilation-error" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Cookie"
		$headerServer0 = "Cache-control: private"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "X-Frame-Origins: SAMEORIGIN"
		$headerServer3 = "Age: 0"
		$headerServer4 = "Via: 1.1 varnish"
		$headerServer5 = "X-Cache: MISS"
		$headerServer6 = "Vary: Accept-Encoding,Fastly-SSL"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_stackoverflowprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable stackoverflow.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/questions/32251817/c-sharp-directives-compilation-error" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en"
		$headerClient2 = "Cookie"
		$headerServer0 = "Cache-control: private"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "X-Frame-Origins: SAMEORIGIN"
		$headerServer3 = "Strict-Transport-Security: max-age=15552000"
		$headerServer4 = "Via: 1.1 varnish"
		$headerServer5 = "Age: 0"
		$headerServer6 = "Connection: close"
		$headerServer7 = "X-Cache: MISS"
		$headerServer8 = "X-Cache-Hits: 0"
		$headerServer9 = "Vary: Fastly-SSL"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_stackoverflowprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable stackoverflow.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/posts/32251817/ivc/7600" fullword
		$uri1 = "/posts/32251816/ivc/7600" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "X-Requested-With: XMLHTTPRequest"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-control: no-cache, no-store, must-revalidate"
		$headerServer1 = "Content-Type: text/plain"
		$headerServer2 = "X-Frame-Options: SAMEORIGIN"
		$headerServer3 = "Via: 1.1 varnish"
		$headerServer4 = "Vary: Fastly-SSL"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_string_of_paerlsprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable string_of_paerls.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/2/R.exe" fullword
		$headerClient0 = "Content-Type: application/x-www-form-urlencoded"
		$headerClient1 = "Cookie"
		$headerServer0 = "Server: Apache/2"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Vary: User-Agent"
		$headerServer3 = "Content-Type: application/octet-stream"
		$headerUserAgent = "Mozilla/4.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_string_of_paerlsprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable string_of_paerls.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/boss/image.php" fullword
		$headerClient0 = "Content-Type: application/x-www-form-urlencoded"
		$headerServer0 = "Server: Apache/2"
		$headerServer1 = "X-Powered-By: PHP/5.3.28"
		$headerServer2 = "Vary: User-Agent"
		$headerServer3 = "Content-Type: application/octet-stream"
		$headerUserAgent = "Mozilla/4.0"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_taidoorprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable taidoor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/login.jsp" fullword
		$uri1 = "/parse.jsp" fullword
		$uri2 = "/page.jsp" fullword
		$uri3 = "/default.jsp" fullword
		$uri4 = "/index.jsp" fullword
		$uri5 = "/process.jsp" fullword
		$uri6 = "/security.jsp" fullword
		$uri7 = "/user.jsp" fullword
		$headerClient0 = "Connection: Keep-Alive"
		$headerClient1 = "Cache-Control: no-cache"
		$headerServer0 = "Server: Microsoft-IIS/5.0"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_taidoorprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable taidoor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/submit.jsp" fullword
		$headerClient0 = "Connection: Keep-Alive"
		$headerClient1 = "Cache-Control: no-cache"
		$headerServer0 = "Server: Microsoft-IIS/5.0"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_templateprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable template.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/login" fullword
		$uri1 = "/config" fullword
		$uri2 = "/admin" fullword
		$headerClient0 = "Host: whatever.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_templateprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable template.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Login" fullword
		$uri1 = "/Config" fullword
		$uri2 = "/Admin" fullword
		$headerClient0 = "Host: whatever.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en"
		$headerClient3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_templateprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable template.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Console" fullword
		$uri1 = "/console" fullword
		$headerClient0 = "Host: whatever.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_templateprofile_httpgetvariant
{
	meta:
		description = "Detects possible C2 malleable template.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/index" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_templateprofile_httppostvariant
{
	meta:
		description = "Detects possible C2 malleable template.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/html" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trevorprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable trevor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/us/ky/louisville/312-s-fourth-st.html" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Referer: https://locations.smashburger.com/us/ky/louisville.html"
		$headerClient3 = "Connection: close"
		$headerClient4 = "Cookie"
		$headerServer0 = "Content-Type: text/html; charset=utf-8"
		$headerServer1 = "Etag: \"57507b788e9ddc737aae615d6bcfc875\""
		$headerServer2 = "Server: AmazonS3"
		$headerServer3 = "Last-Modified: on, 23 Oct 2017 20:50:49 GMT"
		$headerServer4 = "Vary: Accept-Encoding"
		$headerServer5 = "X-Amz-Id-2: 1bGgvQSuG7u4T5qWKlikvJ//uxb9tKkDsbSDOV8YBxhKk64Ij3ygUMxZQ="
		$headerServer6 = "X-Amz-Request-Id: AC1346376B07D"
		$headerServer7 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trevorprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable trevor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/OrderEntryService.asmx/AddOrderLine" fullword
		$headerClient0 = "Accept: */*'    "
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "X-Requested-With: XMLHttpRequest"
		$headerClient3 = "Cookie"
		$headerServer0 = "Cache-Control: private, max-age=0"
		$headerServer1 = "Content-Type: application/json; charset=utf-8"
		$headerServer2 = "Vary: Accept-Encoding"
		$headerServer3 = "Server: Microsoft-IIS/7.5"
		$headerServer4 = "X-AspNet-Version: 4.0.30319"
		$headerServer5 = "X-Powered-By: ASP.NET"
		$headerServer6 = "X-UA-Compatible: IE=Edge"
		$headerServer7 = "X-Frame-Options: SAMEORIGIN"
		$headerServer8 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trevorprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable trevor.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/menus.aspx" fullword
		$uri1 = "/Menus.aspx" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "Referer: https://locations.smashburger.com/us/ky/louisville/312-s-fourth-st.html"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Cache-Control: private"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Location: /Time.aspx"
		$headerServer3 = "Server: Microsoft-IIS/7.5"
		$headerServer4 = "X-AspNet-Version: 4.0.30319"
		$headerServer5 = "Set-Cookie: OrderMode=1; path=/"
		$headerServer6 = "X-Powered-By: ASP.NET"
		$headerServer7 = "X-UA-Compatible: IE=Edge"
		$headerServer8 = "X-Frame-Options: SAMEORIGIN"
		$headerServer9 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trickbotprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable trickbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$headerClient0 = "Host: 203.150.19.63:443"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cache-Control: no-cache"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Date: Fri, 30 Jun 2017 13:08:47 GMT"
		$headerServer2 = "Content-Type: text/html';      "
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)"

	condition:
		all of ($header*)
}

rule possibleC2malleable_trickbotprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable trickbot.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/response.php" fullword
		$headerClient0 = "Content-Type: multipart/form-data; boundary=----ZMZTCR"
		$headerClient1 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Date: Fri, 30 Jun 2017 13:08:47 GMT"
		$headerServer2 = "Content-Type: text/html; charset=utf-8';       "
		$headerServer3 = "Connection: keep-alive"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trick_ryukprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable trick_ryuk.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/dd05ce3a-a9c9-4018-8252-d579eed1e670.zip" fullword
		$headerClient0 = "Accept: text/html, application/xhtml+xml, */*"
		$headerClient1 = "Accept-Language: en-US"
		$headerClient2 = "Host: 23.95.97.59"
		$headerClient3 = "Connection: Keep-Alive"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "Upgrade: h2,h2c"
		$headerServer2 = "Connection: Upgrade, Keep-Alive"
		$headerServer3 = "Last-Modified: Wed, 25 Sep 2019 08:23:20 GMT"
		$headerServer4 = "ETag: \"9d441d3-dda-5935c5d9faea6-gzip\""
		$headerServer5 = "Accept-Ranges: bytes"
		$headerServer6 = "Vary: Accept-Encoding,User-Agent"
		$headerServer7 = "Keep-Alive: timeout=5"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trick_ryukprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable trick_ryuk.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ono19/ADMIN-DESKTOP.AC3B679F4A22738281E6D7B0C5946E42/81/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Content-Type: multipart/form-data; boundary=-----------KMOGEEQTLQTCQMYE"
		$headerServer0 = "Connection: close"
		$headerServer1 = "Server: Cowboy"
		$headerServer2 = "Content-Type: text/plain"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trick_ryukprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable trick_ryuk.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/dd05ce3a-a9c9-4018-8252-D579eed1e670.zip" fullword
		$uri1 = "/Dd05ce3a-a9c9-4018-8252-d579eed1e670.zip" fullword
		$headerClient0 = "Host: 51.254.25.115"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache"
		$headerServer1 = "Upgrade: h2,h2c"
		$headerServer2 = "Connection: Upgrade, Keep-Alive"
		$headerServer3 = "Last-Modified: Wed, 25 Sep 2019 08:23:20 GMT"
		$headerServer4 = "ETag: \"9d441d3-dda-5935c5d9faea6-gzip\""
		$headerServer5 = "Accept-Ranges: bytes"
		$headerServer6 = "Vary: Accept-Encoding,User-Agent"
		$headerServer7 = "Keep-Alive: timeout=5"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trick_ryukprofile_httpgetvariant
{
	meta:
		description = "Detects possible C2 malleable trick_ryuk.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/files" fullword
		$headerClient0 = "Cookie"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_trick_ryukprofile_httppostvariant
{
	meta:
		description = "Detects possible C2 malleable trick_ryuk.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/id" fullword
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ursnif_IcedIDprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable ursnif_IcedID.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/images/U2gVFoeT1Sh8s/" fullword
		$headerClient0 = "Host: jititliste.com"
		$headerClient1 = "Accept: text/html, application/xhtml+xml, */*"
		$headerClient2 = "Accept-Language: en-US"
		$headerClient3 = "DNT: 1"
		$headerClient4 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache/2.2.22 (Debian)"
		$headerServer1 = "X-Powered-By: PHP/5.4.45-0+deb7u14"
		$headerServer2 = "Pragma: no-cache"
		$headerServer3 = "Set-Cookie: lang=en; expires=Sat, 08-Dec-2018 15:50:58 GMT; path=/; domain=.jititliste.com; id="
		$headerServer4 = "Vary: Accept-Encoding"
		$headerServer5 = "Keep-Alive: timeout=5, max=100';"
		$headerServer6 = "Connection: Keep-Alive';"
		$headerServer7 = "Content-Type: text/html"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ursnif_IcedIDprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable ursnif_IcedID.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/data2.php" fullword
		$headerClient0 = "Host: themiole.biz"
		$headerClient1 = "Upgrade: websocket"
		$headerClient2 = "Connection: Upgrade'  "
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: openresty"
		$headerServer1 = "Connection: upgrade"
		$headerServer2 = "Sec-Websocket-Accept: Kfh9QIsMVZc16xEPYxPHzW8SZ8w-"
		$headerServer3 = "Upgrade: websocket"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_ursnif_IcedIDprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable ursnif_IcedID.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/WES/Fatog.php" fullword
		$uri1 = "/WES/fatog.php" fullword
		$headerClient0 = "Host: mnesenesse.com"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: Apache/2.2.15 (CentOS)"
		$headerServer1 = "X-Powered-By: PHP/7.2.11"
		$headerServer2 = "Content-Discription: File Transfer"
		$headerServer3 = "Content-Disposition: attachment; filename=\"ledo2.xap\""
		$headerServer4 = "Content-Type: application/octet-stream"
		$headerServer5 = "Cache-Control: must-revalidate"
		$headerServer6 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_webbugprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable webbug.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/__utm.gif" fullword
		$headerServer0 = "Content-Type: image/gif"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_webbugprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable webbug.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/___utm.gif" fullword
		$headerClient0 = "Content-Type: application/octet-stream"
		$headerServer0 = "Content-Type: image/gif"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_webbug_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable webbug_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/___utm.gif" fullword
		$headerServer0 = "Content-Type: image/gif"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_webbug_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable webbug_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/__utm.gif" fullword
		$headerServer0 = "Content-Type: image/gif"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_webbug_getonlyprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable webbug_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/_init.gif" fullword
		$uri1 = "/__init.gif" fullword
		$headerServer0 = "Content-Type: image/gif"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_wikipedia_getonlyprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable wikipedia_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/w/index.php" fullword
		$headerClient0 = "Host: en.wikipedia.org"
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;"
		$headerClient2 = "Referer: https://en.wikipedia.org/wiki/Main_Page"
		$headerServer0 = "Server: mw1178.eqiad.wmnet"
		$headerServer1 = "X-Powered-By: HHVM/3.12.7"
		$headerServer2 = "X-Content-Type-Options: nosniff"
		$headerServer3 = "P3P: CP=This is not a P3P policy! See https://en.wikipedia.org/wiki/Special:CentralAutoLogin/P3P for more info."
		$headerServer4 = "Vary: Accept-Encoding,X-Forwarded-Proto,Cookie,Authorization"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_wikipedia_getonlyprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable wikipedia_getonly.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/wiki" fullword
		$headerClient0 = "Host: en.wikipedia.org"
		$headerClient1 = "Accept: text/html,application/xhtml+xml,application/xml;"
		$headerClient2 = "Referer"
		$headerServer0 = "Server: mw1178.eqiad.wmnet"
		$headerServer1 = "X-Powered-By: HHVM/3.12.7"
		$headerServer2 = "X-Content-Type-Options: nosniff"
		$headerServer3 = "P3P: CP=This is not a P3P policy! See https://en.wikipedia.org/wiki/Special:CentralAutoLogin/P3P for more info."
		$headerServer4 = "Vary: Accept-Encoding,X-Forwarded-Proto,Cookie,Authorization"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_windowsupdatesprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable windows-updates.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/c/msdownload/update/others/2020/10/29136388_" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: download.windowsupdate.com"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: Microsoft-IIS/8.5"
		$headerServer1 = "X-Powered-By: ASP.NET"
		$headerServer2 = "Content-Encoding: application/vnd.ms-cab-compressed"
		$headerUserAgent = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_windowsupdatesprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable windows-updates.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/c/msdownload/update/others/2020/10/28986731_" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: download.windowsupdate.com"
		$headerServer0 = "Server: Microsoft-IIS/8.5"
		$headerServer1 = "X-Powered-By: ASP.NET"
		$headerServer2 = "Content-Encoding: application/vnd.ms-cab-compressed"
		$headerUserAgent = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_xbashprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable xbash.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/m.png" fullword
		$headerClient0 = "Host: png.realtimenews.tk"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Cookie"
		$headerServer0 = "Server: cloudflare"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "Connection: keep-alive"
		$headerServer3 = "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self"
		$headerServer4 = "X-Github-Request-Id: 7184:5EA1:1693DD4:1EEFFEA:5B9FC138"
		$headerServer5 = "Via: 1.1 varnish"
		$headerServer6 = "X-Served-By: cache-hhn1544-HHN"
		$headerServer7 = "X-Cache: MISS"
		$headerServer8 = "X-Cache-Hits: 0"
		$headerServer9 = "CF-RAY: 45bc6f44849e9706-FRA"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET4.0E; QQBrowser/7.0.3698.400)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_xbashprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable xbash.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/domain/all" fullword
		$headerClient0 = "Host: scan.censys.xyz"
		$headerClient1 = "Accept-Encoding: identity"
		$headerClient2 = "Accept-Language: en-US,en;q=0.8"
		$headerClient3 = "Accept: */*"
		$headerClient4 = "Accept-Charset: ISO-8859-1,utf-8"
		$headerClient5 = "Cookie"
		$headerServer0 = "Server: cloudflare"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "CF-RAY: 455f7b1280ac5368-MIA"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET4.0E; QQBrowser/7.0.3698.400)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_xbashprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable xbash.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/port/tcp8080" fullword
		$uri1 = "/cidir" fullword
		$headerClient0 = "Host: png.realtimenews.tk"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: cloudflare"
		$headerServer1 = "Content-Type: text/html; charset=utf-8"
		$headerServer2 = "CF-RAY: 455f7b1280ac5368-MIA"
		$headerUserAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET4.0E; QQBrowser/7.0.3698.400)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_youtube_videoprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable youtube_video.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/watch" fullword
		$headerClient0 = "Host: www.youtube.com"
		$headerClient1 = "Accept: */*"
		$headerClient2 = "Accept-Language: en-US,en;q=0.5"
		$headerClient3 = "Connection: close"
		$headerClient4 = "Cookie"
		$headerServer0 = "Expires: Tue, 27 Apr 1971 19:44:06 EST"
		$headerServer1 = "P3P: CP='This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=en for more info."
		$headerServer2 = "X-XSS-Protection: 1; mode=block; report=https://www.google.com/appserve/security-bugs/log/youtube"
		$headerServer3 = "Strict-Transport-Security: max-age=31536000"
		$headerServer4 = "Cache-Control: no-cache"
		$headerServer5 = "X-Frame-Options: SAMEORIGIN"
		$headerServer6 = "X-Content-Type-Options: nosniff"
		$headerServer7 = "Content-Type: text/html; charset=utf-8"
		$headerServer8 = "Server: YouTube Frontend Proxy"
		$headerServer9 = "Set-Cookie: YSC=LT4ZGGSgKoE; path=/; domain=.youtube.com; httponly"
		$headerServer10 = "Alt-Svc: quic=':443'; ma=2592000; v='41,39,38,37,35"
		$headerServer11 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_youtube_videoprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable youtube_video.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/ptracking" fullword
		$headerClient0 = "Host: www.youtube.com"
		$headerClient1 = "Accept: */*'    "
		$headerClient2 = "Accept-Language: en"
		$headerClient3 = "Referer: https://www.youtube.com/watch?v=iRXJXaLV0n4' "
		$headerClient4 = "Cookie"
		$headerServer0 = "Strict-Transport-Security: max-age=31536000"
		$headerServer1 = "X-XSS-Protection: 1; mode=block; report=https://www.google.com/appserve/security-bugs/log/youtube"
		$headerServer2 = "Content-Length: 0"
		$headerServer3 = "Cache-Control: no-cache"
		$headerServer4 = "Expires: Tue, 27 Apr 1971 19:44:06 EST"
		$headerServer5 = "X-Frame-Options: SAMEORIGIN"
		$headerServer6 = "Content-Type: video/x-flv"
		$headerServer7 = "X-Content-Type-Options: nosniff"
		$headerServer8 = "Server: YouTube Frontend Proxy"
		$headerServer9 = "Alt-Svc: quic=':443'; ma=2592000; v='41,39,38,37,35"
		$headerServer10 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_youtube_videoprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable youtube_video.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/youtubei/v1/" fullword
		$uri1 = "/youtubei/V1/" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Accept-Language: en-US,en;q=0.5"
		$headerClient2 = "X-Goog-Visitor-Id: CgtGbFYxTWlKTU96VQ=="
		$headerClient3 = "X-YouTube-Client-Name: 56"
		$headerClient4 = "X-YouTube-Client-Version: 20171026"
		$headerClient5 = "Connection: close"
		$headerServer0 = "Cache-Control: no-cache"
		$headerServer1 = "Content-Type: text/xml; charset=UTF-8"
		$headerServer2 = "X-Frame-Options: SAMEORIGIN"
		$headerServer3 = "X-Content-Type-Options: nosniff"
		$headerServer4 = "Strict-Transport-Security: max-age=31536000"
		$headerServer5 = "Content-Length: 155"
		$headerServer6 = "Expires: Tue, 27 Apr 1971 19:44:06 EST"
		$headerServer7 = "Date: Fri, 27 Oct 2017 18:24:28 GMT"
		$headerServer8 = "Server: YouTube Frontend Proxy"
		$headerServer9 = "X-XSS-Protection: 1; mode=block"
		$headerServer10 = "Alt-Svc: quic=':443'; ma=2592000; v='41,39,38,37,35"
		$headerServer11 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zeusprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable zeus.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/metro91/admin/1/ppptp.jpg" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Close"
		$headerClient2 = "Host: mahamaya1ifesciences.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerClient4 = "Cookie"
		$headerServer0 = "Server: nginx/1.0.4"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: close"
		$headerServer3 = "X-Powered-By: PHP/5.3.8-1~dotdeb.2"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zeusprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable zeus.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/metro91/admin/1/secure.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Connection: Keep-Alive"
		$headerClient2 = "Host: mahamaya1ifesciences.com"
		$headerClient3 = "Cache-Control: no-cache"
		$headerServer0 = "Server: nginx/1.0.4"
		$headerServer1 = "Content-Type: text/html"
		$headerServer2 = "Connection: close"
		$headerServer3 = "X-Powered-By: PHP/5.3.8-1~dotdeb.2"
		$headerUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zloaderprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable zloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/wp-content/themes/calliope/wp_data.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: wmwifbajxxbcxmucxmlc.com"
		$headerClient2 = "Connection: Keep-Alive"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: application/x-msdos-program"
		$headerServer2 = "Connection: close"
		$headerServer3 = "Last-Modified: Fri, 24 Apr 2020 23:06:05 GMT"
		$headerServer4 = "ETag: \"76200-5a41168e83140\""
		$headerServer5 = "Accept-Ranges: bytes"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zloaderprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable zloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/post.php" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Cache-Control: no-cache"
		$headerClient2 = "Host: wmwifbajxxbcxmucxmlc.com"
		$headerClient3 = "Connection: close"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zloaderprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable zloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/wp-content/themes/wp-front.php" fullword
		$uri1 = "/wp-content/themes/wp_data.php" fullword
		$headerClient0 = "Host: wmwifbajxxbcxmucxmlc.com"
		$headerClient1 = "Connection: Keep-Alive"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: text/html; charset=UTF-8"
		$headerServer2 = "Connection: close"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zloaderprofile_httpgetvariant
{
	meta:
		description = "Detects possible C2 malleable zloader.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/files/april24.dll" fullword
		$headerClient0 = "Accept: */*"
		$headerClient1 = "Host: wmwifbajxxbcxmucxmlc.com"
		$headerClient2 = "Connection: Keep-Alive"
		$headerClient3 = "Cookie"
		$headerServer0 = "Server: nginx"
		$headerServer1 = "Content-Type: application/x-msdos-program"
		$headerServer2 = "Connection: close"
		$headerServer3 = "Last-Modified: Fri, 24 Apr 2020 23:06:05 GMT"
		$headerServer4 = "ETag: \"76200-5a41168e83140\""
		$headerServer5 = "Accept-Ranges: bytes"
		$headerUserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zoomprofile_httpget
{
	meta:
		description = "Detects possible C2 malleable zoom.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/s/58462514417" fullword
		$uri1 = "/wc/58462514417" fullword
		$headerClient0 = "Connection: close"
		$headerClient1 = "Sec-Fetch-Site: same-origin"
		$headerClient2 = "Sec-Fetch-Mode: navigate"
		$headerClient3 = "Sec-Fetch-User: ?1"
		$headerClient4 = "Sec-Detch-Dest: document"
		$headerClient5 = "Cookie"
		$headerServer0 = "Content-Type: text/html;charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: ZOOM"
		$headerServer3 = "X-Robots-Tag: noindex, nofollow"
		$headerServer4 = "X-Content-Type-Options: nosniff"
		$headerUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16C104"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zoomprofile_httppost
{
	meta:
		description = "Detects possible C2 malleable zoom.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/meeting/save" fullword
		$headerClient0 = "Connection: close"
		$headerClient1 = "Sec-Fetch-Site: same-origin"
		$headerClient2 = "Sec-Fetch-Mode: navigate"
		$headerClient3 = "Sec-Detch-Dest: document"
		$headerClient4 = "Cookie"
		$headerClient5 = "ZOOM-CSRFTOKEN"
		$headerServer0 = "Content-Type: text/html;charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: ZOOM"
		$headerServer3 = "X-Robots-Tag: noindex, nofollow"
		$headerServer4 = "X-Content-Type-Options: nosniff"
		$headerUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16C104"

	condition:
		1 of ($uri*) and all of ($header*)
}

rule possibleC2malleable_zoomprofile_httpstager
{
	meta:
		description = "Detects possible C2 malleable zoom.profile"
		author = "Lee Kirkpatrick (RSA IR)"
		date = "2021-05-14"
		license = "https://creativecommons.org/licenses/by-nc-sa/4.0/"

	strings:
		$uri0 = "/Signin" fullword
		$uri1 = "/signin" fullword
		$headerClient0 = "Connection: close"
		$headerClient1 = "Sec-Fetch-Site: same-origin"
		$headerClient2 = "Sec-Fetch-Mode: navigate"
		$headerClient3 = "Sec-Fetch-User: ?1"
		$headerClient4 = "Sec-Detch-Dest: document"
		$headerServer0 = "Content-Type: text/html;charset=utf-8"
		$headerServer1 = "Connection: close"
		$headerServer2 = "Server: ZOOM"
		$headerServer3 = "X-Robots-Tag: noindex, nofollow"
		$headerServer4 = "X-Content-Type-Options: nosniff"
		$headerUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16C104"

	condition:
		1 of ($uri*) and all of ($header*)
}

