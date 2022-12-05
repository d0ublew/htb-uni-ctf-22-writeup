# Fake News (Forensics - Easy)

1. analyze timeline, sort by modification time, look from earliest date

```sh
$ ls -alt ./html/
```

2. Look for files that have been changed between a certain period of time. Not sure the efficien way to investigate the file. Just gut feeling that the file is either there by default and so does the content

```sh
$ find ./html/ -type f -newermt '2022-09-01' \! -newermt '2022-10-01' | wc -l

$ find ./html/ -type f -newermt '2022-10-01' \! -newermt '2022-11-01' | wc -l

$ find ./html/ -type f -newermt '2022-11-01' \! -newermt '2022-11-08' | wc -l

$ find ./html/ -type f -newermt '2022-11-08' \! -newermt '2022-11-15' | wc -l

$ find ./html/ -type f -newermt '2022-11-15' \! -newermt '2022-11-22' | wc -l

$ find ./html/ -type f -newermt '2022-11-22' \! -newermt '2022-11-29' | wc -l

$ find ./html/ -type f -newermt '2022-11-23' \! -newermt '2022-11-24' | wc -l

$ find ./html/ -type f -newermt '2022-11-24' \! -newermt '2022-11-25' | wc -l

$ find ./html/ -type f -newermt '2022-11-25' \! -newermt '2022-11-26' | wc -l

$ find ./html/ -type f -newermt '2022-11-25' \! -newermt '2022-11-26' | xargs stat
```

3. Between 25 Nov 2022 and 26 Nov 2022, `./html/wp-content/plugins/plugin-manager/plugin-manager.php` is the first to be modified
4. Inspect the file, found base64 then decode it, we found part 1 of the flag
5. Moving forward
6. Noticed obfuscated javascript in `./html/wp-blogs/2022/11/index.php`
7. Run the javascript in isolated environment, which downloaded a `PE64` executable file
8. Analyze it with [`floss`](https://github.com/mandiant/flare-floss), which is the next level of `strings` tool that only works with `PE` file
9. Run `floss` and found the part 2 of the flag
