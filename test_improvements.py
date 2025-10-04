#!/usr/bin/env python3
"""
Test script for XSSProbe improvements
"""

def test_imports():
    """Test that all modules can be imported without errors"""
    try:
        from lib.core import core
        from lib.crawler.crawler import crawler
        from lib.helper.helper import session
        from lib.helper.Log import Log
        from lib.dom_xss import DOMXSSDetector
        from lib.config import Config
        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_config():
    """Test the configuration system"""
    try:
        from lib.config import Config
        
        # Test URL validation
        assert Config.validate_url("http://example.com") == True
        assert Config.validate_url("invalid-url") == False
        
        # Test safe filename generation
        filename = Config.get_safe_filename("http://example.com/test?param=1")
        assert len(filename) > 0
        assert filename.endswith('.txt')
        
        print("✅ Configuration tests passed")
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_core_initialization():
    """Test core scanner initialization"""
    try:
        from lib.core import core
        
        scanner = core()
        assert scanner.target is None
        assert scanner.session is None
        
        print("✅ Core initialization test passed")
        return True
    except Exception as e:
        print(f"❌ Core initialization test failed: {e}")
        return False

def test_logging():
    """Test logging functionality"""
    try:
        from lib.helper.Log import Log
        
        Log.info("Test info message")
        Log.warning("Test warning message")
        Log.high("Test critical message")
        
        print("✅ Logging tests passed")
        return True
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        return False

def run_tests():
    """Run all tests"""
    print("🧪 Running XSSProbe improvement tests...\n")
    
    tests = [
        test_imports,
        test_config,
        test_core_initialization,
        test_logging
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Code quality improvements are working correctly.")
    else:
        print("⚠️  Some tests failed. Please review the issues above.")
    
    return passed == total

if __name__ == "__main__":
    run_tests()