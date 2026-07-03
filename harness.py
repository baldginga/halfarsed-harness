check_headers(base_url, results)
    check_tls(hostname, results)
    check_cors(base_url, results)
    check_common_paths(base_url, results)
    check_error_verbosity(base_url, results)

    # --- Generate a unique filename ---
    clean_identifier = hostname.replace(".", "_") if hostname else "unknown_target"
    time_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    filename = f"report_{clean_identifier}_{time_str}.json"
    
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
        
    print(f"\n[*] Full report written to {filename}")

    print("[*] This harness covers infra/config checks only.")
    print("[*] Run manual_test_cases.md for the XSS / prompt-injection / rate-limit checks")
    print("[*] that need a human to actually submit the form and look at the result.")


if __name__ == "__main__":
    main()
