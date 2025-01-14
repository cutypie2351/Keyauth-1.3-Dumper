## Keyauth-1.3-Dumper
Keyauth v1.3 Server Side Dumper Tool made by Cutypie.

- **what it do?** any files or bytes from the Keyauth server will be dumped into a dump folder.
- **what is Keyauth?** Keyauth is a public authentication system with client SDK, more info can be found here: https://keyauth.cc/
- **how its work?** the DLL hooks the keyauth request function, decrypts the data and put the server response bytes into a bin file. 
- **more info:** its also bypassing integrity_check, cmd_error, signature_check and more...
## Build:
- 1. extract the polyhook2-static.zip
- 2. open the sln file and build the project using CTRL + B
  
## Tutorial - How To Use:
- 1. Open the target Keyauth loader process
  2. Login with a valid username and password or license key
  3. Inject the dll to the process using any injector that you want. (Can be LoadLibaryA injection or Manual Map injection).

__**Video Tutorial:**__
https://streamable.com/srwy18

**Note:** make sure you inject the dll **after** you logged in!

if you find any bugs or its doesnt work for you, open issues on this project
