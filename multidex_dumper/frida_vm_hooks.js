setImmediate(function () {
    let Color = {
        Reset: '\x1b[39;49;00m',
        Black: '\x1b[30;01m', Blue: '\x1b[34;01m', Cyan: '\x1b[36;01m', Gray: '\x1b[37;11m',
        Green: '\x1b[32;01m', Purple: '\x1b[35;01m', Red: '\x1b[31;01m', Yellow: '\x1b[33;01m',
        Light: {
            Black: '\x1b[30;11m', Blue: '\x1b[34;11m', Cyan: '\x1b[36;11m', Gray: '\x1b[37;01m',
            Green: '\x1b[32;11m', Purple: '\x1b[35;11m', Red: '\x1b[31;11m', Yellow: '\x1b[33;11m'
        }
    };

    var fs = require('frida-fs');

    let sent_files = [];

    function detectAPKFile(content) {
        if (content[0] == 0x50 &&
            content[1] == 0x4B &&
            content[2] == 0x03 &&
            content[3] == 0x04 &&
            content[4] == 0x14) {
            return true;
        }

        return false;
    }

    function detectDEXFile(content) {
        if (content[0] == 0x64 &&
            content[1] == 0x65 &&
            content[2] == 0x78) {
            return true;
        }

        return false;
    }

    function last_name(str) {
        return str.substring(str.lastIndexOf('/') + 1);
    }

    function copy_file_to_tmp(path, content) {
        var temporal_path = path + ".bk";
        console.log("[+] Copying file " + path + " to " + temporal_path);
        var temp_file = new File(temporal_path, "w")
        temp_file.write(content)
        temp_file.close()
        return temporal_path;
    }

    //============================================================
    // check for open
    Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
        onEnter(args) {
            const filename = Memory.readUtf8String(args[0]);

            console.log(Color.Green + "[+] File opened: ", filename, Color.Reset);

            if (!sent_files.includes(filename)) {
                try {
                    var stats = fs.statSync(filename);

                    if (stats.isDirectory()) {
                        console.log("[+] Path " + filename + " is a directory...");
                    }
                    else {
                        var content = fs.readFileSync(filename);

                        if (detectAPKFile(content)) {
                            console.log(Color.Red + "[+] Detected open of APK file, logging in...", Color.Reset);
                            send({ "dumped_file": filename, 'content': content });
                            sent_files.push(filename)
                        }
                        else if (detectDEXFile(content)) {
                            console.log(Color.Red + "[+] Detected open of DEX file, logging in...", Color.Reset)
                            send({ "dumped_file": filename, 'content': content });
                            sent_files.push(filename)
                        }
                    }
                } catch (error) {
                    console.log("[-] Error in open: " + error.toString());
                }
            }

        }
    });
    //============================================================

    //============================================================
    // avoid delete 
    Interceptor.attach(Module.findExportByName('libc.so', 'unlink'), {
        onEnter(args) {
            const filename = Memory.readUtf8String(args[0]);

            console.log(Color.Red + "[!] unlink called from the app, trying to remove file: " + filename, Color.Reset);

            if (!sent_files.includes(filename)) {
                try {
                    var stats = fs.statSync(filename);

                    if (stats.isDirectory()) {
                        console.log("[+] Path " + filename + " is a directory...");
                    }
                    else {
                        var content = fs.readFileSync(filename);

                        if (detectAPKFile(content)) {
                            console.log(Color.Red + "[+] Detected unlink of APK file, avoiding...", Color.Reset);
                            send({ "dumped_file": filename, 'content': content });
                            sent_files.push(filename)
                        }
                        else if (detectDEXFile(content)) {
                            console.log(Color.Red + "[+] Detected unlink of DEX file, avoiding...", Color.Reset)
                            send({ "dumped_file": filename, 'content': content });
                            sent_files.push(filename)
                        }
                    }
                } catch (error) {
                    console.log("[-] Error in close: " + error.toString());
                }
            }
        }
    });
    //============================================================

    Java.perform(function () {

        function getRandomString(length) {
            var randomChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            var result = '';
            for (var i = 0; i < length; i++) {
                result += randomChars.charAt(Math.floor(Math.random() * randomChars.length));
            }
            return result;
        }

        //============================================================
        let dexpathlist = Java.use("dalvik.system.DexPathList");

        dexpathlist.loadDexFile.implementation = function (file, optimizedDirectory, loader, elements) {
            var file_name = file.getAbsolutePath();
            console.log(Color.Red + "[+] Detected a loadDexFile call in the sample: " + file_name, Color.Reset);
            return this.loadDexFile(file, optimizedDirectory, loader, elements);
        }

        dexpathlist.makePathElements.overload("java.util.List", "java.io.File", "java.util.List").implementation = function (files, optimizedDirectory, supressedExceptions) {
            console.log(Color.Red + "[!] Done somekind of weird DEX loading...", Color.Reset);
            
            var list_of_files = Java.cast(files, Java.use("java.util.List"));
            var length = list_of_files.size();

            console.log(list_of_files);

            console.log("[+] List of files:");

            for (var i = 0; i < length; i++) {
                send({"loaded_file":list_of_files.get(i)});
            }
        
            return this.makePathElements(files, optimizedDirectory, supressedExceptions);
        }
        //============================================================


        //============================================================
        // Class hook
        let classDef = Java.use("java.lang.Class")


        // hook getMethod class
        classDef.getDeclaredMethod.implementation = function (name, parametersType) {
            console.log(Color.Green + "[+] Class.getDeclaredMethod called, method loaded: " + name, Color.Reset);

            send({ "loaded_method": name });

            return this.getDeclaredMethod(name, parametersType);
        }
        //============================================================

        //============================================================
        let javaFiles = Java.use("java.nio.file.Files")

        // hook copy method
        javaFiles.copy.overload('java.io.InputStream', 'java.nio.file.Path', '[Ljava.nio.file.CopyOption;').implementation = function (input, path, option) {
            console.log(Color.Green + "[+] Copy a file to " + path.toString(), Color.Reset);

            var return_value = this.copy(input, path, option);

            var content = fs.readFileSync(path.toString());

            if (detectAPKFile(content)) {
                console.log(Color.Red + "[!] Detected a copy of an APK file, reporting.", Color.Reset);

                if (!sent_files.includes(path.toString())) {
                    send({ "dumped_file": path.toString(), 'content': content });
                    sent_files.push(path.toString())
                }
            }
            else if (detectDEXFile(content)) {
                console.log(Color.Red + "[!] Detected a copy of a DEX file, reporting.", Color.Reset);
                if (!sent_files.includes(path.toString())) {
                    send({ "dumped_file": path.toString(), 'content': content });
                    sent_files.push(path.toString())
                }
            }

            return return_value;
        }
        //============================================================

        //============================================================
        // Work with the File class
        let javaFile = Java.use("java.io.File");

        javaFile.createTempFile.overload('java.lang.String', 'java.lang.String').implementation = function (prefix, suffix) {
            console.log(Color.Green + "[+] Created a file with prefix: " + prefix + " and suffix " + suffix, Color.Reset);
            return this.createTempFile(prefix, suffix);
        }

        javaFile.createTempFile.overload('java.lang.String', 'java.lang.String', "java.io.File").implementation = function (prefix, suffix, directory) {
            var directoryName = directory.getAbsolutePath();

            console.log(Color.Green + "[+] Created a file with prefix: " + prefix + " and suffix: " + suffix + " in the directory: " + directoryName, Color.Reset);

            return this.createTempFile(prefix, suffix, directory);
        }

        javaFile.delete.overload().implementation = function () {
            var fileName = this.getAbsolutePath();

            console.log(Color.Green + "[+] Trying to remove the file: " + fileName, Color.Reset);

            var content = fs.readFileSync(fileName);

            if (detectAPKFile(content)) {
                console.log(Color.Red + "[+] Detected delete of APK file, avoiding...", Color.Reset);
                send({ "dumped_file": fileName });
            }
            else if (detectDEXFile(content)) {
                console.log(Color.Red + "[+] Detected delete of DEX file, avoiding...", Color.Reset);
                send({ "dumped_file": fileName });
            }
            else {
                this.delete();
            }
        }
        //============================================================

        //============================================================
        // Check for output streams...
        /*
        let InflaterOutputStream = Java.use("java.util.zip.InflaterOutputStream");
        let FilterOutputStream = Java.use("java.io.FilterOutputStream");
        let OutputStream = Java.use("java.io.OutputStream");

        InflaterOutputStream.write.overload("[B", "int", "int").implementation = function (b, off, len) {
            console.log(Color.Green + "[+] Detected a write to an OutputStream", Color.Reset);
            if (detectAPKFile(b)) {
                console.log(Color.Red + "[+] Detected write of APK file, copying to another location...", Color.Reset);
                var temp_file = "/data/local/tmp/" + getRandomString(5);
                var file = new File(temp_file);
                file.write(b);
                file.close();
            }
            else if (detectDEXFile(b)) {
                console.log(Color.Red + "[+] Detected write of DEX file, copying to another location...", Color.Reset);
                var temp_file = "/data/local/tmp/" + getRandomString(5);
                var file = new File(temp_file);
                file.write(b);
                file.close();
            }
        }

        FilterOutputStream.write.overload("[B", "int", "int").implementation = function (b, off, len) {
            console.log(Color.Green + "[+] Detected a write to an OutputStream", Color.Reset);
            if (detectAPKFile(b)) {
                console.log(Color.Red + "[+] Detected write of APK file, copying to another location...", Color.Reset);
                var temp_file = "/data/local/tmp/" + getRandomString(5);
                var file = new File(temp_file);
                file.write(b);
                file.close();
            }
            else if (detectDEXFile(b)) {
                console.log(Color.Red + "[+] Detected write of DEX file, copying to another location...", Color.Reset);
                var temp_file = "/data/local/tmp/" + getRandomString(5);
                var file = new File(temp_file);
                file.write(b);
                file.close();
            }
        }

        // OutputStream.write(i)
        OutputStream.write.overload("int").implementation = function (i) {
            console.log("OutputStream.write(int)");
            OutputStream.write.overload("int").call(this, i);
        }

        // OutputStream.write(byte[])
        OutputStream.write.overload("[B").implementation = function (bArr) {
            try {
                console.log("OutputStream.write(byte[]) (" + bArr.length + ")");
            } catch (e) {
                console.log("OutputStream.write(byte[]) (" + bArr.value.length + ")");
            }
            OutputStream.write.overload("[B").call(this, bArr);
        }

        // OutputStream.write(byte[], off, len)
        OutputStream.write.overload("[B", "int", "int").implementation = function (bArr, offset, len) {
            console.log("OutputStream.write(byte[], offset: " + offset + ", len: " + len + ")");
            OutputStream.write.overload("[B", "int", "int").call(this, bArr, offset, len);
        }
        */
        //============================================================

        //============================================================
        let basedexclassloader = Java.use("dalvik.system.BaseDexClassLoader");

        basedexclassloader.$init.overload('java.lang.String', 'java.io.File', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectroy, librarySearchPath, parent) {
            console.log(Color.Green + "[+] BaseDexClassLoader $init called! Pathfile: ", dexPath, Color.Reset);

            // call original function
            this.$init(dexPath, optimizedDirectroy, librarySearchPath, parent);
        }
        //============================================================

        //============================================================
        // DexClassLoader hook
        let dexclassLoader = Java.use("dalvik.system.DexClassLoader")
        // hook constructor method
        dexclassLoader.$init.implementation = function (dexPath, optimizedDirectroy, librarySearchPath, parent) {
            console.log(Color.Green + "[+] DexClassLoader $init called! Pathfile: ", dexPath, Color.Reset);

            // call original function
            this.$init(dexPath, optimizedDirectroy, librarySearchPath, parent);
        }

        dexclassLoader.loadClass.overload('java.lang.String').implementation = function (class_name) {
            console.log(Color.Green + "[+] Class loaded dynamically: " + class_name, Color.Reset);

            send({ "loaded_class": class_name });

            return this.loadClass(class_name);
        }
        //============================================================


        //============================================================
        let classLoaderDef = Java.use('java.lang.ClassLoader');

        let loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');

        // hook loadClass method
        loadClass.implementation = function (class_name) {
            console.log(Color.Green + "[+] DexClassLoader.loadClass, class loaded: ", class_name, Color.Reset);
            return this.loadClass(class_name)
        }
        //============================================================


    });

});