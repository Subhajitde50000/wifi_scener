def cmd_research_ui(args) -> int:
    from wifiscanner.research.ui import start_ui_server
    
    # We aggregate all databases or use a central one.
    db_path = f"sqlite:///{args.db}" if getattr(args, "db", None) else "sqlite:///research_labs.sqlite"
    
    try:
        start_ui_server(db_path, args.bind, args.port)
    except KeyboardInterrupt:
        print("\nResearch UI stopped.")
    except Exception as e:
        print(f"Failed to start UI: {e}")
        return 1
    return 0
