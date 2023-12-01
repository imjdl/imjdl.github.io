cmd.exe /c bundle exec jekyll b
# 设置源目录和目标目录
$sourceDir = "E:\\Project\\blog\\_site"
$targetDir = "E:\\Project\\blog\\remote"

Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force

Set-Location -Path $targetDir

git add *

git commit -m "更新博客"

git push origin main
