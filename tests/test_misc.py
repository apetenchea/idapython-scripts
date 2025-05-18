def test_output_logging(run_ida):
    result = run_ida(
        script="misc/output_logging.py",
        sample="83226a8c8c55106a3f6081a9344c749b.pe",
    )

    assert result == 1
