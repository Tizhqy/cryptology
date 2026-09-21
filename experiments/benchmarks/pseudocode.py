"""PSEUDOCODE: Key exchange benchmark ve JSON/CSV export."""


def benchmark(provider_factory, repeat_count=15):
    results = []
    for run_number in range(repeat_count):
        start = monotonic_ns()
        provider = provider_factory.create()
        generation_ms = elapsed_ms(start)

        start = monotonic_ns()
        exchange_result = provider.establish_with_in_memory_peer()
        exchange_ms = elapsed_ms(start)

        results.append({
            "run": run_number + 1,
            "key_generation_ms": generation_ms,
            "key_exchange_ms": exchange_ms,
            "network_bytes": exchange_result.encoded_frame_bytes,
        })

    # Ham tekrarlar JSON'a, ortalama ve standart sapma CSV/JSON summary'e yazilir.
    write_json(results)
    write_summary_csv(calculate_statistics(results))
    return results
