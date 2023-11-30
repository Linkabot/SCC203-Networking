HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 3961
Connection: keep-alive
Last-Modified: Thu, 04 Nov 2021 18:27:33 GMT
Accept-Ranges: bytes
Server: AmazonS3
Date: Thu, 24 Feb 2022 16:41:38 GMT
ETag: "41f0211ff315bbd7e2b6dc2e98143935"
Vary: Accept-Encoding
Cache-Control: public, max-age=86400
X-Cache: Hit from cloudfront
Via: 1.1 3ed6913225a2751cd6347e2088d1f5fa.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: MAN50-C2
X-Amz-Cf-Id: yvWeV1quE6Vn6P-06UcK-jFH0lW1j8DFmJhyjRJ1wIYs7aBdvlaHSA==
Age: 74669

<html>
	<head>
		<title>NeverSSL - Connecting ... </title>
		<style>
		body {
			font-family: Montserrat, helvetica, arial, sans-serif;
			font-size: 16x;
			color: #444444;
			margin: 0;
		}
		h2 {
			font-weight: 700;
			font-size: 1.6em;
			margin-top: 30px;
		}
		p {
			line-height: 1.6em;
		}
		.container {
			max-width: 650px;
			margin: 20px auto 20px auto;
			padding-left: 15px;
			padding-right: 15px
		}
		.header {
			background-color: #42C0FD;
			color: #FFFFFF;
			padding: 10px 0 10px 0;
			font-size: 2.2em;
		}
		.notice {
			background-color: red;
			color: white;
			padding: 10px 0 10px 0;
			font-size: 1.25em;
			animation: flash 4s infinite;
		}
		@keyframes flash {
		0% {
			background-color: red;
		}
		50% {
			background-color: #AA0000;
		}
		0% {
			background-color: red;
		}
		}
		<!-- CSS from Mark Webster https://gist.github.com/markcwebster/9bdf30655cdd5279bad13993ac87c85d -->
		</style>

		<script>
			var adjectives = [ 'cool' , 'calm' , 'relaxed', 'soothing', 'serene', 'slow',
							'beautiful', 'wonderful', 'wonderous', 'fun', 'good',
							'glowing', 'inner', 'grand', 'majestic', 'astounding',
							'fine', 'splendid', 'transcendent', 'sublime', 'whole',
							'unique', 'old', 'young', 'fresh', 'clear', 'shiny',
							'shining', 'lush', 'quiet', 'bright', 'silver' ];

			var nouns =	  [ 'day', 'dawn', 'peace', 'smile', 'love', 'zen', 'laugh',
							'yawn', 'poem', 'song', 'joke', 'verse', 'kiss', 'sunrise',
							'sunset', 'eclipse', 'moon', 'rainbow', 'rain', 'plan',
							'play', 'chart', 'birds', 'stars', 'pathway', 'secret',
							'treasure', 'melody', 'magic', 'spell', 'light', 'morning'];

			var prefix =
					// Choose 3 zen adjectives
					adjectives.sort(function(){return 0.5-Math.random()}).slice(-3).join('')
					+
					// Coupled with a zen noun
					nouns.sort(function(){return 0.5-Math.random()}).slice(-1).join('');
			window.location.href = 'http://' + prefix + '.neverssl.com/online';
		</script>
	</head>
	<body>
	<noscript>
		<div class="notice">
			<div class="container">
				⚠️ JavaScript appears to be disabled. NeverSSL's cache-busting works better if you enable JavaScript for <code>neverssl.com</code>.
			</div>
		</div>
	</noscript>
	<div class="header">
		<div class="container">
		<h1>NeverSSL</h1>
		</div>
	</div>
	<div class="content">
	<div class="container">

	<h1 id="status"></h1>
	<script>document.querySelector("#status").textContent = "Connecting ...";</script>
	<noscript>

		<h2>What?</h2>
		<p>This website is for when you try to open Facebook, Google, Amazon, etc
		on a wifi network, and nothing happens. Type "http://neverssl.com"
		into your browser's url bar, and you'll be able to log on.</p>

		<h2>How?</h2>
		<p>neverssl.com will never use SSL (also known as TLS). No
		encryption, no strong authentication, no <a
		href="https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security">HSTS</a>,
		no HTTP/2.0, just plain old unencrypted HTTP and forever stuck in the dark
		ages of internet security.</p>

		<h2>Why?</h2>
		<p>Normally, that's a bad idea. You should always use SSL and secure
		encryption when possible. In fact, it's such a bad idea that most websites
		are now using https by default.</p>

		<p>And that's great, but it also means that if you're relying on
		poorly-behaved wifi networks, it can be hard to get online.  Secure
		browsers and websites using https make it impossible for those wifi
		networks to send you to a login or payment page. Basically, those networks
		can't tap into your connection just like attackers can't. Modern browsers
		are so good that they can remember when a website supports encryption and
		even if you type in the website name, they'll use https.</p>

		<p>And if the network never redirects you to this page, well as you can
		see, you're not missing much.</p>

        <a href="https://twitter.com/neverssl">Follow @neverssl</a>

	</noscript>

	</div>
	</div>

	</body>
</html>
