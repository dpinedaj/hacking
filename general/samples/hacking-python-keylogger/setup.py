from cx_Freeze import setup, Executable

setup(
    name="Hello World File",
    version="1.0",
    description="Testing",
    executables=[Executable("test.py")],
)