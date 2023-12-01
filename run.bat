: bundle exec jekyll s --lsi
@echo off
bundle exec jekyll b
xcopy /s /y _site\* /remote
