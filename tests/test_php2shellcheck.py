import asyncio
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
from aiohttp import web

import php2shellcheck as p


class ClassifyTests(unittest.TestCase):
    def status(self, text):
        return p.classify(p.parse_version(text))[0]

    def test_unpatched_supported_branches(self):
        for text in ("PHP/8.2.34", "PHP/8.3.0", "PHP/8.4.26", "PHP/8.5.9"):
            self.assertEqual(self.status(text), p.VULNERABLE, text)

    def test_fixed_releases_and_later(self):
        for text in ("PHP/8.2.35", "PHP/8.3.36", "PHP/8.4.27", "PHP/8.5.12", "PHP/8.5.13"):
            self.assertEqual(self.status(text), p.PATCHED, text)

    def test_end_of_life(self):
        for text in ("PHP/8.1.14", "PHP/8.1", "PHP/7.4.33", "PHP/5.6.40", "PHP/7"):
            self.assertEqual(self.status(text), p.END_OF_LIFE, text)

    def test_unknown(self):
        self.assertEqual(p.classify(None)[0], p.UNKNOWN)
        for text in ("PHP/8", "PHP/8.2", "PHP/8.6.0"):
            self.assertEqual(self.status(text), p.UNKNOWN, text)

    def test_distro_build_is_flagged(self):
        status, note = p.classify(p.parse_version("PHP/8.3.6-0ubuntu0.24.04.5"))
        self.assertEqual(status, p.VENDOR_BUILD)
        self.assertIn("backported", note)
        status, _note = p.classify(p.parse_version("PHP/8.1.2-1ubuntu2.20"))
        self.assertEqual(status, p.VENDOR_BUILD)

    def test_distro_build_of_old_branch_is_end_of_life(self):
        status, note = p.classify(p.parse_version("PHP/7.2.24-0ubuntu0.18.04.17"))
        self.assertEqual(status, p.END_OF_LIFE)
        self.assertIn("backported", note)

    def test_upstream_tracking_builds_keep_their_status(self):
        for text in ("PHP/8.2.20-1+ubuntu22.04.1+deb.sury.org+1", "PHP/8.3.10-r0-alpine"):
            self.assertEqual(self.status(text), p.VULNERABLE, text)
        self.assertEqual(self.status("PHP/8.2.35-1+deb12u1"), p.PATCHED)

    def test_server_header_vendor(self):
        rhel = [("Server", "Apache/2.4.37 (Red Hat Enterprise Linux)"), ("X-Powered-By", "PHP/7.4.33")]
        self.assertEqual(p.host_status(p.matching_headers(rhel, 443, "https")), p.VENDOR_BUILD)
        centos = [("Server", "Apache/2.4.6 (CentOS) PHP/7.4.33")]
        self.assertEqual(p.host_status(p.matching_headers(centos, 80, "http")), p.END_OF_LIFE)
        plain = [("Server", "nginx"), ("X-Powered-By", "PHP/8.3.6")]
        self.assertEqual(p.host_status(p.matching_headers(plain, 80, "http")), p.VULNERABLE)


class HeaderTests(unittest.TestCase):
    def test_signals_from_each_header(self):
        headers = [
            ("X-Powered-By", "ASP.NET, PHP/8.2.12"),
            ("Server", "Apache/2.4.58 (Ubuntu) PHP/8.1.2"),
            ("Set-Cookie", "PHPSESSID=abc; path=/"),
            ("X-Powered-By", "Express"),
            ("Server", "nginx"),
        ]
        sources = [source for source, _value, _version, _vendor in p.extract_signals(headers)]
        self.assertEqual(sources, ["X-Powered-By", "Server", "Set-Cookie"])

    def test_header_cannot_forge_report_lines(self):
        found = p.matching_headers([("X-Powered-By", "PHP/8.2.1\r\nHost: evil")], 80, "http")
        self.assertEqual(len(found), 1)
        self.assertNotIn("\n", found[0][1])

    def test_host_status_prefers_versioned_signal(self):
        patched = p.matching_headers(
            [("X-Powered-By", "PHP/8.5.12"), ("Set-Cookie", "PHPSESSID=x")], 80, "http"
        )
        self.assertEqual(p.host_status(patched), p.PATCHED)
        mixed = p.matching_headers(
            [("X-Powered-By", "PHP/8.5.12"), ("Server", "Apache PHP/8.1.2")], 80, "http"
        )
        self.assertEqual(p.host_status(mixed), p.END_OF_LIFE)


class TargetTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(
            p.parse_ports(p.DEFAULT_PORT_SPEC),
            [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")],
        )
        self.assertEqual(
            p.parse_ports("443, 9000, 9001/http, 9000/https, 7000-7002/HTTPS"),
            [(443, "https"), (9000, None), (9001, "http"), (7000, "https"), (7001, "https"), (7002, "https")],
        )
        for spec in ("", "0", "65536", "80,abc", "9000/ftp", "1-65535", "90-80", "-80"):
            with self.assertRaises(ValueError, msg=spec):
                p.parse_ports(spec)

    def test_local_addresses(self):
        for text in ("127.0.0.1", "127.8.9.1", "0.0.0.0", "::1", "::", "169.254.169.254", "fe80::1%eth0", "::ffff:127.0.0.1"):
            self.assertTrue(p.is_local_address(text), text)
        for text in ("10.0.0.5", "192.168.1.1", "8.8.8.8", "2001:db8::1", "not-an-ip"):
            self.assertFalse(p.is_local_address(text), text)

    def test_cidr_expansion(self):
        self.assertEqual(p.expand_network("192.0.2.0/30"), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(p.expand_network("192.0.2.7/32"), ["192.0.2.7"])
        self.assertEqual(p.expand_network("10.0.0.0/8"), [])
        self.assertIsNone(p.expand_network("example.com"))

    def test_load_targets(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("# web\n192.0.2.0/30\n192.0.2.1\nexample.com\nhttp://x/\n10.0.0.0/8\n")
        try:
            hosts, skipped, duplicates = p.load_targets(handle.name)
        finally:
            os.unlink(handle.name)
        self.assertEqual(hosts, ["192.0.2.1", "192.0.2.2", "example.com"])
        self.assertEqual((skipped, duplicates), (2, 1))

    def test_host_from_url(self):
        for value in (
            "https://www.capehenlopenschools.com/",
            "http://www.capehenlopenschools.com:8080/path?q=1#top",
            "www.capehenlopenschools.com/",
            "www.capehenlopenschools.com",
            " WWW.CapeHenlopenSchools.com. ",
        ):
            self.assertEqual(
                p.host_from_url(value).lower(), "www.capehenlopenschools.com", value
            )
        self.assertEqual(p.host_from_url("capehenlopenschools.com"), "capehenlopenschools.com")
        self.assertEqual(p.host_from_url("https://192.0.2.5/"), "192.0.2.5")
        self.assertEqual(p.host_from_url("https://[2001:db8::1]:8443/"), "2001:db8::1")
        self.assertEqual(p.host_from_url("2001:db8::1"), "2001:db8::1")
        for value in ("", "ftp://example.com/", "https:///", "http://exa mple.com/", "http://x:bad/"):
            self.assertIsNone(p.host_from_url(value), value)

    def test_same_origin_redirect(self):
        url = "http://example.com:80/"
        self.assertEqual(
            p.same_origin_redirect("/app/", url, "example.com", 80, "http"),
            "http://example.com:80/app/",
        )
        self.assertEqual(
            p.same_origin_redirect("http://example.com/x", url, "example.com", 80, "http"),
            "http://example.com/x",
        )
        for location in ("https://example.com/", "http://other.com/", "http://example.com:8080/"):
            self.assertIsNone(p.same_origin_redirect(location, url, "example.com", 80, "http"))


class ReportTests(unittest.TestCase):
    def test_summary_counts_unreachable_and_file_mode(self):
        finished = [
            ("a", True, p.matching_headers([("X-Powered-By", "PHP/8.2.12")], 80, "http")),
            ("b", True, p.matching_headers([("X-Powered-By", "PHP/8.5.12")], 80, "http")),
            ("c", True, []),
            ("d", False, []),
        ]
        findings, totals = p.summarize(finished)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "out.txt")
            p.write_report(path, findings, totals, 0, 0, 0)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertIn("Host: a [VULNERABLE]", text)
        self.assertIn("Host: b [PATCHED]", text)
        self.assertIn("Responded on at least one probed port: 3", text)
        self.assertIn("No HTTP response on any probed port: 1", text)
        self.assertIn("Hosts with vulnerability indicators: 1 of 3 responding", text)
        self.assertEqual(mode, 0o600)


class LiveCheckTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def root(request):
            raise web.HTTPFound("/app/")

        async def app(request):
            return web.Response(text="ok", headers={"X-Powered-By": "PHP/8.4.20"})

        async def static_root(request):
            return web.Response(text="static")

        async def index_php(request):
            return web.Response(text="ok", headers={"X-Powered-By": "PHP/8.3.36"})

        async def offsite(request):
            raise web.HTTPFound("http://other.invalid/")

        self.runners = []
        async def admin_console(request):
            return web.Response(text="ok", headers={"X-Powered-By": "PHP/8.5.9"})

        self.redirect_port = await self.serve([("/", root), ("/app/", app)])
        self.console_port = await self.serve([("/", admin_console)])

        async def chain_root(request):
            raise web.HTTPFound("/portal/", headers={"X-Powered-By": "PHP/8.4.5"})

        async def chain_mid(request):
            raise web.HTTPFound("user/", headers={"X-Powered-By": "PHP/8.4.5"})

        async def chain_end(request):
            return web.Response(text="ok", headers={"X-Powered-By": "PHP/8.4.5"})

        self.chain_port = await self.serve(
            [("/", chain_root), ("/portal/", chain_mid), ("/portal/user/", chain_end)]
        )
        self.fallback_port = await self.serve([("/", static_root), ("/index.php", index_php)])
        self.offsite_port = await self.serve([("/", offsite)])
        self.session = aiohttp.ClientSession()
        self.semaphore = asyncio.Semaphore(4)

    async def serve(self, routes):
        application = web.Application()
        for path, handler in routes:
            application.router.add_get(path, handler)
        runner = web.AppRunner(application)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        self.runners.append(runner)
        return runner.addresses[0][1]

    async def asyncTearDown(self):
        await self.session.close()
        for runner in self.runners:
            await runner.cleanup()

    async def check(self, port):
        return await p.check_target(self.session, "127.0.0.1", port, "http", self.semaphore)

    async def test_follows_same_host_redirect(self):
        responded, indicators = await self.check(self.redirect_port)
        self.assertTrue(responded)
        self.assertEqual(p.host_status(indicators), p.VULNERABLE)
        self.assertIn("/app/", indicators[0][1])

    async def test_redirect_chain_reports_header_once(self):
        responded, indicators = await self.check(self.chain_port)
        self.assertTrue(responded)
        self.assertEqual(len(indicators), 1)
        self.assertNotIn("/portal/", indicators[0][1])

    async def test_fallback_path(self):
        responded, indicators = await self.check(self.fallback_port)
        self.assertTrue(responded)
        self.assertEqual(p.host_status(indicators), p.PATCHED)
        self.assertIn("/index.php", indicators[0][1])

    async def test_offsite_redirect_not_followed(self):
        responded, indicators = await self.check(self.offsite_port)
        self.assertTrue(responded)
        self.assertEqual(indicators, [])

    async def test_unknown_port_falls_back_to_http(self):
        responded, indicators = await p.check_target(
            self.session, "127.0.0.1", self.console_port, None, self.semaphore
        )
        self.assertTrue(responded)
        self.assertEqual(p.host_status(indicators), p.VULNERABLE)
        self.assertIn(f"[Port {self.console_port}/HTTP]", indicators[0][1])

    async def test_unknown_closed_port_is_not_responding(self):
        responded, indicators = await p.check_target(
            self.session, "127.0.0.1", 1, None, self.semaphore
        )
        self.assertFalse(responded)
        self.assertEqual(indicators, [])

    async def test_hostname_resolving_to_loopback_is_not_probed(self):
        resolver = p.ExternalResolver()
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver))
        try:
            responded, indicators = await p.check_target(
                session, "localhost", self.console_port, "http", self.semaphore
            )
        finally:
            await session.close()
            await resolver.close()
        self.assertFalse(responded)
        self.assertEqual(indicators, [])
        self.assertEqual(resolver.local_hosts, {"localhost"})

    async def test_closed_port_is_not_responding(self):
        responded, indicators = await self.check(1)
        self.assertFalse(responded)
        self.assertEqual(indicators, [])


if __name__ == "__main__":
    unittest.main()
