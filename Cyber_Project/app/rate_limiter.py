"""
Rate Limiter for Login Brute Force Protection.
Implements exponential backoff: 5 failed attempts = 5 min lockout × 2^n.
"""

import time
from datetime import datetime, timedelta
from flask import session


class RateLimiter:
    """Manages login rate limiting with exponential backoff."""
    
    MAX_ATTEMPTS = 5  # Maximum failed attempts before lockout
    BASE_LOCKOUT_MINUTES = 5  # Initial lockout duration
    
    # In-memory storage for failed attempts (would use Redis in production)
    _failed_attempts = {}  # {username: {'count': int, 'lockout_until': float, 'lockout_multiplier': int}}
    
    @classmethod
    def check_rate_limit(cls, username: str) -> tuple[bool, str, int]:
        """
        Check if user is rate limited.
        
        Args:
            username: The username attempting to log in
            
        Returns:
            Tuple of (is_allowed, message, seconds_remaining)
        """
        username_lower = username.lower()
        
        if username_lower not in cls._failed_attempts:
            return True, "", 0
        
        user_data = cls._failed_attempts[username_lower]
        lockout_until = user_data.get('lockout_until', 0)
        
        if lockout_until > 0:
            current_time = time.time()
            
            if current_time < lockout_until:
                remaining = int(lockout_until - current_time)
                minutes = remaining // 60
                seconds = remaining % 60
                
                message = f"Account temporarily locked. Try again in {minutes}m {seconds}s."
                return False, message, remaining
            else:
                # Lockout expired, reset count but keep multiplier
                user_data['count'] = 0
                user_data['lockout_until'] = 0
        
        return True, "", 0
    
    @classmethod
    def record_failed_attempt(cls, username: str) -> tuple[bool, str, int]:
        """
        Record a failed login attempt.
        
        Args:
            username: The username that failed login
            
        Returns:
            Tuple of (is_locked, message, lockout_seconds)
        """
        username_lower = username.lower()
        
        if username_lower not in cls._failed_attempts:
            cls._failed_attempts[username_lower] = {
                'count': 0,
                'lockout_until': 0,
                'lockout_multiplier': 1
            }
        
        user_data = cls._failed_attempts[username_lower]
        user_data['count'] += 1
        
        attempts_remaining = cls.MAX_ATTEMPTS - user_data['count']
        
        if user_data['count'] >= cls.MAX_ATTEMPTS:
            # Calculate lockout duration with exponential backoff
            multiplier = user_data['lockout_multiplier']
            lockout_minutes = cls.BASE_LOCKOUT_MINUTES * multiplier
            lockout_seconds = lockout_minutes * 60
            
            user_data['lockout_until'] = time.time() + lockout_seconds
            user_data['lockout_multiplier'] = multiplier * 2  # Double for next lockout
            user_data['count'] = 0  # Reset count for next round
            
            message = f"Too many failed attempts. Account locked for {lockout_minutes} minutes."
            
            # Print to console for monitoring
            print(f"\n{'!'*50}")
            print(f"  RATE LIMIT TRIGGERED")
            print(f"  Username: {username}")
            print(f"  Locked for: {lockout_minutes} minutes")
            print(f"  Next lockout will be: {lockout_minutes * 2} minutes")
            print(f"{'!'*50}\n")
            
            return True, message, lockout_seconds
        
        message = f"Invalid credentials. {attempts_remaining} attempts remaining."
        return False, message, 0
    
    @classmethod
    def record_successful_login(cls, username: str):
        """
        Record a successful login, resetting the failure count.
        
        Args:
            username: The username that logged in successfully
        """
        username_lower = username.lower()
        
        if username_lower in cls._failed_attempts:
            # Reset count but keep multiplier to prevent abuse
            cls._failed_attempts[username_lower]['count'] = 0
            cls._failed_attempts[username_lower]['lockout_until'] = 0
    
    @classmethod
    def get_attempts_remaining(cls, username: str) -> int:
        """Get number of login attempts remaining before lockout."""
        username_lower = username.lower()
        
        if username_lower not in cls._failed_attempts:
            return cls.MAX_ATTEMPTS
        
        count = cls._failed_attempts[username_lower].get('count', 0)
        return max(0, cls.MAX_ATTEMPTS - count)
    
    @classmethod
    def reset_user(cls, username: str):
        """Completely reset rate limiting for a user (admin function)."""
        username_lower = username.lower()
        if username_lower in cls._failed_attempts:
            del cls._failed_attempts[username_lower]
