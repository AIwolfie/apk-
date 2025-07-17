import subprocess

apk_path = "C:\Apktool\nab-connect.apk"
decompiled_path = "C:\Apktool"

command = [
    'java', '-jar', 'C:/Apktool/apktool.jar',
    'd', apk_path,
    '-o', decompiled_path,
    '-f'
]

result = subprocess.run(command, capture_output=True, text=True)

print(result.stdout)
print(result.stderr)
