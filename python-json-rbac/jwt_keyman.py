#!/usr/bin/env python3
"""
Command-line utility for JWT key management operations.
"""
import sys
import argparse
import json
import os
from pathlib import Path
from typing import Optional

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from key_manager import (
        get_key_manager,
        validate_current_secret,
        generate_secure_secret,
        create_rotation_plan,
    )
    from config import get_secret_info, generate_new_secret
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the correct directory")
    sys.exit(1)


def cmd_generate(args) -> None:
    """Generate a new secure secret."""
    secret = generate_secure_secret(args.length)
    
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(secret)
        print(f"Secret written to {args.output_file}")
    else:
        print("Generated secure secret:")
        print(secret)
    
    if args.show_info:
        # Temporarily validate the generated secret
        from config import _calculate_entropy
        print(f"\nSecret info:")
        print(f"  Length: {len(secret)} characters")
        print(f"  Entropy: {_calculate_entropy(secret):.2f} bits/char")


def cmd_validate(args) -> None:
    """Validate the current JWT secret configuration."""
    try:
        validation = validate_current_secret()
        
        print("JWT Secret Validation Report")
        print("=" * 40)
        
        if validation["valid"]:
            print("✅ Secret configuration is valid")
        else:
            print("⚠️  Secret configuration has issues")
        
        print(f"Security Score: {validation['security_score']}/100")
        
        if validation["recommendations"]:
            print("\nRecommendations:")
            for i, rec in enumerate(validation["recommendations"], 1):
                print(f"  {i}. {rec}")
        
        if args.verbose:
            print("\nSecret Information:")
            info = validation["secret_info"]
            print(f"  Algorithm: {info['algorithm']}")
            print(f"  Secret Length: {info['secret_length']} characters")
            print(f"  Entropy: {info['entropy_estimate']:.2f} bits/char")
            print(f"  JWE Enabled: {info['jwe_enabled']}")
            print(f"  Key Rotation: {info['key_rotation_enabled']}")
            print(f"  Strict Mode: {info['strict_mode']}")
        
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        sys.exit(1)


def cmd_rotate(args) -> None:
    """Perform key rotation."""
    try:
        manager = get_key_manager(args.storage_path)
        
        if args.dry_run:
            plan = create_rotation_plan()
            print("Key Rotation Plan (Dry Run)")
            print("=" * 30)
            print(f"Action: {plan['action']}")
            print(f"Message: {plan['message']}")
            if 'urgency' in plan:
                print(f"Urgency: {plan['urgency']}")
            return
        
        print("Performing key rotation...")
        new_secret, new_key_id = manager.rotate_key(
            new_algorithm=args.algorithm,
            new_length=args.length
        )
        
        print(f"✅ Key rotation completed")
        print(f"New Key ID: {new_key_id}")
        
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(new_secret)
            print(f"New secret written to {args.output_file}")
        else:
            print("New secret:")
            print(new_secret)
        
        print("\n⚠️  Important: Update your JWT_SECRET environment variable!")
        print("   Set JWT_SECRET_PREVIOUS to your old secret for graceful rotation")
        
    except Exception as e:
        print(f"❌ Key rotation failed: {e}")
        sys.exit(1)


def cmd_status(args) -> None:
    """Show key management status."""
    try:
        manager = get_key_manager(args.storage_path)
        status = manager.get_rotation_status()
        
        print("Key Management Status")
        print("=" * 25)
        
        if status["active_key_id"]:
            print(f"Active Key ID: {status['active_key_id']}")
            if status["active_key_age_hours"] is not None:
                print(f"Key Age: {status['active_key_age_hours']:.1f} hours ({status['active_key_age_hours']/24:.1f} days)")
            print(f"Rotation Count: {status['rotation_count']}")
            if status["last_used"]:
                print(f"Last Used: {status['last_used']}")
        else:
            print("No active key found")
        
        print(f"Total Keys: {status['total_keys']}")
        print(f"Inactive Keys: {status['inactive_keys']}")
        
        if args.verbose:
            keys = manager.list_keys(include_inactive=True)
            if keys:
                print("\nAll Keys:")
                for key_id, metadata in keys.items():
                    status_symbol = "🔑" if metadata.is_active else "🔒"
                    print(f"  {status_symbol} {key_id}: {metadata.algorithm}, "
                          f"created {metadata.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Show rotation plan
        plan = create_rotation_plan()
        print(f"\nRotation Plan: {plan['message']}")
        
    except Exception as e:
        print(f"❌ Status check failed: {e}")
        sys.exit(1)


def cmd_cleanup(args) -> None:
    """Clean up old keys."""
    try:
        manager = get_key_manager(args.storage_path)
        
        if args.dry_run:
            print(f"Dry run: Would remove keys older than {args.max_age_days} days")
            # This is a simplified dry run - a full implementation would show which keys
            return
        
        removed_count = manager.cleanup_old_keys(args.max_age_days)
        print(f"✅ Cleaned up {removed_count} old keys")
        
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")
        sys.exit(1)


def cmd_export_config(args) -> None:
    """Export current configuration for deployment."""
    try:
        info = get_secret_info()
        
        config = {
            "algorithm": info["algorithm"],
            "jwe_enabled": info["jwe_enabled"],
            "secret_length": info["secret_length"],
            "key_rotation_enabled": info["key_rotation_enabled"],
            "recommendations": validate_current_secret()["recommendations"],
        }
        
        if args.output_file:
            with open(args.output_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"Configuration exported to {args.output_file}")
        else:
            print(json.dumps(config, indent=2))
            
    except Exception as e:
        print(f"❌ Export failed: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="JWT Key Management Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s generate --length 64 --output-file .env.new
  %(prog)s validate --verbose
  %(prog)s rotate --dry-run
  %(prog)s status --verbose
  %(prog)s cleanup --max-age-days 30
        """
    )
    
    parser.add_argument(
        '--storage-path',
        help="Path for key metadata storage",
        default=os.getenv("JWT_KEY_STORAGE_PATH", ".jwt_keys.json")
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate a new secure secret')
    gen_parser.add_argument('--length', type=int, default=64, help='Secret length (default: 64)')
    gen_parser.add_argument('--output-file', help='Write secret to file instead of stdout')
    gen_parser.add_argument('--show-info', action='store_true', help='Show secret information')
    gen_parser.set_defaults(func=cmd_generate)
    
    # Validate command
    val_parser = subparsers.add_parser('validate', help='Validate current JWT secret')
    val_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')
    val_parser.set_defaults(func=cmd_validate)
    
    # Rotate command
    rot_parser = subparsers.add_parser('rotate', help='Perform key rotation')
    rot_parser.add_argument('--algorithm', default='HS256', help='Algorithm for new key (default: HS256)')
    rot_parser.add_argument('--length', type=int, default=64, help='New key length (default: 64)')
    rot_parser.add_argument('--output-file', help='Write new secret to file')
    rot_parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    rot_parser.set_defaults(func=cmd_rotate)
    
    # Status command
    stat_parser = subparsers.add_parser('status', help='Show key management status')
    stat_parser.add_argument('--verbose', '-v', action='store_true', help='Show all keys')
    stat_parser.set_defaults(func=cmd_status)
    
    # Cleanup command
    clean_parser = subparsers.add_parser('cleanup', help='Clean up old keys')
    clean_parser.add_argument('--max-age-days', type=int, default=30, help='Maximum age for inactive keys (default: 30)')
    clean_parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    clean_parser.set_defaults(func=cmd_cleanup)
    
    # Export command
    exp_parser = subparsers.add_parser('export-config', help='Export configuration')
    exp_parser.add_argument('--output-file', help='Write config to file instead of stdout')
    exp_parser.set_defaults(func=cmd_export_config)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Check for required environment variables
    if args.command != 'generate' and not os.getenv('JWT_SECRET'):
        print("❌ JWT_SECRET environment variable is required")
        sys.exit(1)
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if os.getenv('DEBUG'):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
