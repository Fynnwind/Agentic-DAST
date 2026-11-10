from dast_analyzer.naming import parse_row_name


def test_base_minting_row():
    n = parse_row_name("", "gitea-user-blind")
    assert (n.target, n.auth, n.role, n.variant) == ("gitea", "user", "blind", "")
    assert n.repeat is None  # minting repeats are numbered run-wise by the index
    assert n.parsed


def test_suffixed_repeat_from_label():
    # triage reps store harness_row without the number, label with it
    n = parse_row_name("gitea-user-blind-rep-1", "gitea-user-blind-rep")
    assert n.variant == "rep" and n.variant_family == "rep" and n.repeat == 1


def test_suffixed_repeat_when_harness_row_has_number():
    # verify reps store the number in harness_row too (label == harness_row)
    n = parse_row_name("gitea-user-blind-rep-2", "gitea-user-blind-rep-2")
    assert n.variant == "rep" and n.repeat == 2


def test_frver2_digit_is_part_of_variant_not_a_repeat():
    n = parse_row_name("gitea-user-blind-frver2", "gitea-user-blind-frver2")
    assert n.variant == "frver2"
    assert n.variant_family == "frver"  # so frontier-verification catches it
    assert n.repeat is None


def test_context_variants():
    for fam in ("codenone", "peernone"):
        n = parse_row_name(f"wordpress-none-blind-{fam}-3", f"wordpress-none-blind-{fam}")
        assert n.variant == fam and n.repeat == 3


def test_verify_config_variants():
    for fam in ("vdet", "vdef", "vllm"):
        n = parse_row_name(f"cacti-user-blind-{fam}-1", f"cacti-user-blind-{fam}")
        assert n.variant_family == fam and n.repeat == 1


def test_crawl_role():
    n = parse_row_name("", "grafana-user-crawl")
    assert n.role == "crawl" and n.parsed


def test_pilot_baseline_is_not_matrix_parsed():
    n = parse_row_name("", "cacti-baseline")
    assert n.parsed is False  # baseline is not a matrix role
    assert n.target == "cacti"
