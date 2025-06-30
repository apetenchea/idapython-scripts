def test_enumerate_segments(run_ida):
    result = run_ida(
        script="core/enumerate_segments.py",
        sample="83226a8c8c55106a3f6081a9344c749b.pe",
        output="enumerate_segments.log",
    )
    assert result == 0


def test_segment_registers(run_ida):
    result = run_ida(
        script="core/segment_registers.py",
        sample="83226a8c8c55106a3f6081a9344c749b.pe",
        output="segment_registers.log",
    )
    assert result == 0


def test_register_values(run_ida):
    result = run_ida(
        script="core/register_values.py",
        sample="83226a8c8c55106a3f6081a9344c749b.pe",
        output="register_values.log",
    )
    assert result == 0
