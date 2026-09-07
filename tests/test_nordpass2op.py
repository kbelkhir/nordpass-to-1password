"""Tests for nordpass2op. Run: python3 -m pytest tests/ -q   (or: python3 tests/test_nordpass2op.py)"""
import csv, json, os, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nordpass2op as n2

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample-nordpass.csv")


class TestParsing(unittest.TestCase):
    def setUp(self):
        self.rows = n2.read_export(FIXTURE)

    def test_reads_crlf_and_bom(self):
        with open(FIXTURE, "rb") as fh:
            raw = fh.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "fixture should carry a BOM")
        self.assertIn(b"\r\n", raw, "fixture should use CRLF")
        self.assertEqual(len(self.rows), 10)

    def test_embedded_newlines_and_commas_survive(self):
        gh = self.rows[0]
        self.assertEqual(gh["note"], "line one\nline two, with comma")
        self.assertEqual(gh["password"], 'p@ss,w"rd\\x')

    def test_rejects_non_nordpass_csv(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write("a,b\n1,2\n")
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                n2.read_export(path)
        finally:
            os.unlink(path)


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.rows = n2.read_export(FIXTURE)
        self.buckets, self.report = n2.analyse(self.rows)

    def test_folder_rows_dropped(self):
        self.assertEqual(self.report["folders"], 1)

    def test_bucket_counts(self):
        self.assertEqual(len(self.buckets["login"]), 3)   # GitHub, untitled, OddType
        self.assertEqual(len(self.buckets["card"]), 3)
        self.assertEqual(len(self.buckets["note"]), 1)
        self.assertEqual(len(self.buckets["identity"]), 1)

    def test_unknown_type_falls_back_to_login(self):
        titles = [t for t, _ in self.buckets["login"]]
        self.assertIn("OddType", titles)

    def test_blank_name_becomes_untitled(self):
        self.assertEqual(self.report["untitled"], 1)
        self.assertIn("(untitled)", [t for t, _ in self.buckets["login"]])

    def test_passkeys_flagged_not_imported(self):
        self.assertEqual(self.report["passkeys"], ["GooglePK"])

    def test_totp_detected(self):
        self.assertIn("GitHub", self.report["totp"])

    def test_bad_expiry_flagged(self):
        self.assertEqual(len(self.report["bad_expiry"]), 1)
        self.assertEqual(self.report["bad_expiry"][0][1], "BadExp")

    def test_nothing_silently_dropped(self):
        placed = sum(len(v) for v in self.buckets.values())
        accounted = (placed + self.report["folders"]
                     + len(self.report["passkeys"]) + len(self.report["unknown"]))
        self.assertEqual(accounted, len(self.rows))


class TestExpiry(unittest.TestCase):
    def test_formats(self):
        for raw, want in (("7/28", "07/2028"), ("07/2028", "07/2028"),
                          ("2029-03", "03/2029"), ("12.30", "12/2030"), ("", "")):
            self.assertEqual(n2.norm_expiry(raw), (want, True), raw)

    def test_unparseable_passes_through_flagged(self):
        self.assertEqual(n2.norm_expiry("next year"), ("next year", False))

    def test_rejects_impossible_month(self):
        self.assertFalse(n2.norm_expiry("13/2028")[1])


class TestCsvOutput(unittest.TestCase):
    def setUp(self):
        self.rows = n2.read_export(FIXTURE)
        self.buckets, _ = n2.analyse(self.rows)
        self.dir = tempfile.mkdtemp()
        n2.write_csvs(self.buckets, self.dir)

    def test_validation_passes(self):
        self.assertTrue(n2.validate(self.buckets, self.dir))

    def test_round_trips_hostile_values(self):
        with open(os.path.join(self.dir, "op-logins.csv"), newline="", encoding="utf-8") as fh:
            out = list(csv.DictReader(fh))
        gh = next(r for r in out if r["title"] == "GitHub")
        self.assertEqual(gh["password"], 'p@ss,w"rd\\x')
        self.assertIn("line two, with comma", gh["notes"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes are not meaningful on Windows")
    def test_files_are_private(self):
        for fn in os.listdir(self.dir):
            mode = os.stat(os.path.join(self.dir, fn)).st_mode & 0o777
            self.assertEqual(mode, 0o600, fn)

    def test_card_columns_match_1password_order(self):
        with open(os.path.join(self.dir, "op-cards.csv"), newline="", encoding="utf-8") as fh:
            self.assertEqual(next(csv.reader(fh)), n2.CARD_COLS)


class TestOpTemplates(unittest.TestCase):
    def setUp(self):
        self.rows = n2.read_export(FIXTURE)
        self.buckets, _ = n2.analyse(self.rows)

    def _tmpl(self, kind, title):
        row = next(r for t, r in self.buckets[kind] if t == title)
        return n2.build_template(kind, title, row)

    def test_login_shape(self):
        t = self._tmpl("login", "GitHub")
        self.assertEqual(t["category"], "LOGIN")
        by_id = {f["id"]: f for f in t["fields"]}
        self.assertEqual(by_id["password"]["value"], 'p@ss,w"rd\\x')
        self.assertEqual(by_id["password"]["type"], "CONCEALED")
        self.assertEqual(t["urls"][0]["href"], "https://github.com")
        self.assertEqual(t["tags"], ["Dev"])

    def test_totp_becomes_real_otp_field(self):
        t = self._tmpl("login", "GitHub")
        otp = next(f for f in t["fields"] if f["type"] == "OTP")
        self.assertTrue(otp["value"].startswith("otpauth://"))

    def test_card_month_year_is_yyyymm(self):
        t = self._tmpl("card", "Visa")
        exp = next(f for f in t["fields"] if f["type"] == "MONTH_YEAR")
        self.assertEqual(exp["value"], "202807")

    def test_templates_are_json_serialisable(self):
        for kind in ("login", "card", "identity", "note"):
            for title, row in self.buckets[kind]:
                json.dumps(n2.build_template(kind, title, row))

    def test_no_empty_fields_emitted(self):
        t = self._tmpl("card", "Amex")
        self.assertTrue(all(f.get("value") for f in t["fields"]))


class TestPlatform(unittest.TestCase):
    def test_secure_tmp_base_works_everywhere(self):
        """Must not raise on Windows, where os.getuid does not exist."""
        base = n2.secure_tmp_base()
        self.assertTrue(os.path.isdir(base))

    def test_workspace_creates_usable_dir(self):
        path, _ram = n2.make_workspace()
        try:
            self.assertTrue(os.path.isdir(path))
            probe = os.path.join(path, "probe")
            with open(probe, "w") as fh:
                fh.write("x")
            self.assertTrue(os.path.exists(probe))
        finally:
            import shutil; shutil.rmtree(path, ignore_errors=True)


class TestShred(unittest.TestCase):
    def test_shred_removes_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("secret" * 100)
            path = fh.name
        self.assertTrue(n2.shred_file(path))
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
