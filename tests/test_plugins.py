def test_load_and_apply_pdb(run_ida):
    result = run_ida(
        script="plugins/load_and_apply_pdb.py",
        sample="71ebfc2b0ed9de01e32ef1585f41720a.pe",
        output="load_and_apply_pdb.log",
        extra_plugin_args=["11e08e61c9773f485ff950ddf7f5a0c8.pdb"],
    )

    assert result == 0
