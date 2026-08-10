import unittest

from luxcipher.desktop_app import LuxCipherApp


class DesktopAppTests(unittest.TestCase):
    def test_desktop_app_class_is_importable(self) -> None:
        self.assertIsNotNone(LuxCipherApp)


if __name__ == "__main__":
    unittest.main()
