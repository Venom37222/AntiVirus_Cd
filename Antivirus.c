bool can_scan = false;
//This consists of current path
malwares Path = wide_char_to_wide_string(current_path);
boost::filesystem::path p = { Path };
// we got the extension of the file
std::string extension = p.extension().string();
// if boost scan enabled then it 
// ignores some uncommon extensions like .txt etc.,
if (return_boost_scan_status() == true)
{
if (check_extensions.is_common_extension(extension) == true) 
can_scan = true;
}
// If boost is enabled and the extension is ok 
// then scan and if boost is disabled then scan
if (can_scan == true || return_boost_scan_status() == false)
{
if (check_extensions.is_common_extension(extension) == true)
{
// Increments the scanned file count
increment_file_count();
std::cout << "File: " << Path 
<< "\n" << "extension: 
" << extension << "\n";
// md5 hash of the file is stored here
std::string hash = calculate_md5
(wide_char_to_wide_string(current_path));
std::cout << "Hash: " 
<< hash << "\n";
// Rule 1
// checks in the database whether the hash 
// matches or not and adds to the list
if (check_in_database(hash) == true)
{
std::cout << "\nHash Malicious Executable" 
<< Path << "\n";
add_suspicious_files_to_list
(Path, "Suspicious[IDENTIFIED] executables");
}
// Rule 2
// Checks whether the executable is packed with UPX or not
if (is_upx(Path))
{
std::cout << "\nMalicious 
Executable" << Path << "\n";
add_suspicious_files_to_list
(Path, "Suspicious[PACKED] executables");
}
// Rule 3
// Checks whether the string matches in the exe
if (extension == ".exe")
{
if (is_string_present(0, Path))
{
std::cout << "\nMalicious Executable";
add_suspicious_files_to_list
(Path, "Suspicious Semi-Declared");
int a;
std::cin >> a;
}
}
std::cout << "\nFiles scanned " 
<< return_file_count() << "\n";
}
else
{
std::cout << "Scheduling this path\n";
add_to_schedule(Path);
}
