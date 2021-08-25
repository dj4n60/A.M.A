import requests
import re
import hashlib
import io
import pefile
import struct
import os
import os.path, time
import logging, sys
from os import listdir
from os.path import isfile, join
import subprocess
import time
import json
"""
import logging, sys
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
logging.debug('A debug message!')
logging.info('We processed %d records', len(processed_records))
"""
logging.basicConfig(format='%(message)s \n\r Started: %(asctime)s \n\n',stream=sys.stderr, level=logging.DEBUG)

def convert_bytes(num):
    """
    this function will convert bytes to MB.... GB... etc
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

def file_size(malware):
    """
    :params : malware( to analyze)
    :return : st_size

    Result: malware size
    """
    if os.path.isfile(malware):
        file_info = os.stat(malware)
        return convert_bytes(file_info.st_size)

def avclass(input,output):
    #if len(sys.argv) != 3:
        #print("No such file")
        #sys.exit(1)
    md5 = ""
    sha256 = ""
    sha1 = ""
    first_seen = ""
    scan_date = ""
    av_labels = ""
    with open(input) as f:
        lines = f.readlines()
    with open(output, "w") as f:
        for line in lines:
            try:
                data = json.loads(line, strict=False)
                md5 = data["data"]["attributes"]["md5"]
                sha256 = data["data"]["attributes"]["sha256"]
                sha1 = data["data"]["attributes"]["sha1"]
                first_seen = data["data"]["attributes"]["first_submission_date"]
                scan_date = data["data"]["attributes"]["last_analysis_date"]
                av_labels = []
                last_analysis = data["data"]["attributes"]["last_analysis_results"]
                for av_analysis in last_analysis.keys():
                    tmp = last_analysis[av_analysis]
                    if tmp['category'] == 'malicious':
                        av = tmp['engine_name']
                        malware = tmp['result']
                        av_labels.append([av, malware])
            except Exception as e:
                logging.error(" [-]Error" + str(e))

        res = {"md5": md5, "sha256": sha256, "sha1": sha1,
               "first_seen": first_seen, "scan_date": scan_date, "av_labels": av_labels}
        f.write(json.dumps(res) + "\n")

def VT_Request(key, hash, path , malware):
    """
    :params : key(VirusTotal apikey) , hash (malware hash) , path (Result)
    :return :

    Result: Report from virus total
    """
    if len(key) == 64:
        try:
            print(key+hash)
            id =  hash
            urlx = 'https://www.virustotal.com/api/v3/files/' + id
            headers = {'x-apikey':key }
            url = requests.get( urlx , headers=headers)
            json_response = url.json()
            if json_response:
                with open(path, 'w') as outfile:
                    json.dump(json_response, outfile)
                    logging.info('[-] Written on json')
            else:
                    logging.warning('[-] ' + malware + ' [' + hash + '] is not in Virus Total')
        except Exception as e:
            logging.error("\n [-] Oops!! " + str(e))
    else:
        logging.error(" [-] There is something Wrong With Your API Key.")
        exit()

def Basic_analysis(malware,path):
    """
    :params : malware( to analysis) , path(for write the report)
    :return :

    Result: PE Analysis.txt
    """
    ## Image Type Anlaysis
    logging.info("[*]Basic Analysis" )
    IMAGE_FILE_MACHINE_I386=332
    IMAGE_FILE_MACHINE_IA64=512
    IMAGE_FILE_MACHINE_AMD64=34404

    fl=open(malware, "rb")

    s=fl.read(2)
    if s.decode("ISO-8859-1")!="MZ":
        logging.warning("Not a Exe file" )
    else:
        fl.seek(60)
        s=fl.read(4)
        header_offset=struct.unpack("<L", s)[0]
        fl.seek(header_offset+4)
        s=fl.read(2)
        machine=struct.unpack("<H", s)[0]
        fp=open(path + '.txt','a')
        if machine==IMAGE_FILE_MACHINE_I386:
            logging.info("[*]Image Type = IA-32 (32-bit x86)")
            fp.write("[*]Image Type = IA-32 (32-bit x86)")
            fp.write('\n\n')
            fp.close()
        elif machine==IMAGE_FILE_MACHINE_IA64:
            logging.info("[*]Image Type = IA-64 (Itanium)")
            fp.write("[*]Image Type = IA-64 (Itanium)")
            fp.write('\n\n')
            fp.close()
        elif machine==IMAGE_FILE_MACHINE_AMD64:
            logging.info("[*]Image Type = AMD64 (64-bit x86)")
            fp.write("[*]Image Type = AMD64 (64-bit x86)")
            fp.write('\n\n')
            fp.close()
        else:
            logging.warning("Unknown architecture")
            """
            print '\n File Size = ' + file_size(f)
            print '\n Last Modified Date = %s' % time.ctime(os.path.getmtime(f))
            print '\n Created Date = %s' % time.ctime(os.path.getctime(f))
            """
        fp=open(path + '.txt','a')
        fp.write('File Size = ' + file_size(malware))
        fp.write('\n\nLast Modified Date: %s' % time.ctime(os.path.getmtime(malware)))
        fp.write('\n\nCreated Date: %s' % time.ctime(os.path.getctime(malware)))
        #fp.write('\n')
        #fp.write('\n')
        fp.close()
    fl.close()

def PE_analysis(malware,path):
    """
    :params : malware( to analysis) , path(for write the report)
    :return :

    Result: PE Analysis.txt
    """
## PE File Analysis"
    try:
        logging.info("[*] PE Analysis detailed")

        pe=pefile.PE(malware)

        fp=open(path + '.txt','a')
        fp.write('\n\nImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase))
        fp.write('\n\nAddress Of EntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        fp.write('\n\nNumber Of RvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes ))
        fp.write('\n\nNumber Of Sections = ' + hex(pe.FILE_HEADER.NumberOfSections))
        fp.write('\n\n')

        ## List Import Sections"
        logging.info('[*] Listing Sections')
        fp.write('[*] Listing Sections \n\n')


        for section in pe.sections:
            fp.write('\n ' + section.Name.decode('utf-8'))
            fp.write("\n\n\tVirtual Address: " + hex(section.VirtualAddress))
            fp.write("\n\n\tVirtual Size: " + hex(section.Misc_VirtualSize))
            fp.write("\n\n\tRaw Size: " + hex(section.SizeOfRawData))

        ## List Import DLL"
        fp.write('\n\n\n')
        logging.info("[*] Listing imported DLLs...")
        fp.write('\n[*] Listing imported DLLs...\n')
        for lst in pe.DIRECTORY_ENTRY_IMPORT:
            fp.write('\n'+lst.dll.decode('utf-8'))
            for s in lst.imports:
                fp.write('\n\n' + "\t - %s at 0x%08x" % (unicode(s.name).decode('utf-8'), s.address)+ '\n\n',)

        fp=open(path + '.txt','a')
        logging.info("[*] Listing Header Members...")
        fp.write('\n[*] Listing Header Members...')
        fp.write('\n')

        for headers in pe.DOS_HEADER.dump():
            fp.write('\n')
            fp.write('\n\t' + headers)

        fp.close()

        for ntheader in pe.NT_HEADERS.dump():
            fp=open(path + '.txt','a')
            fp.write('\n')
            fp.write('\n\t' + ntheader)

        fp=open(path + '.txt','a')
        logging.info("[*] Listing Optional Headers...'")
        fp.write('\n[*] Listing Optional Headers...')
        fp.write('\n')
        for optheader in pe.OPTIONAL_HEADER.dump():
            fp.write('\n\t' + optheader)
    except:
        logging.error("[-]" + malware +" DOS Header magic not found.")

def Strings_analysis(malware,path):
    """
    Strings Analysis
    Extracting Strings From File

    :params : malware
    :return : md5_hash
    """
    logging.info("[*] Strings Analysis ")
    list_files = subprocess.run(["strings", malware], stdout=subprocess.PIPE,text=True)

    fp=open(path + '.txt','a')
    fp.write(list_files.stdout)
    fp.close()

    #### Count Hash Value###
    with io.open(malware, mode="rb") as fd:
        content = fd.read()
        md5_hash = hashlib.md5(content).hexdigest()
    logging.info('[//] MD5 Hash Value Of Your File Is :- ' + str(md5_hash))

    return md5_hash

def main():
    #create report folder
    if os.path.exists(os.getcwd() +'/reports/'):
        pass
    else:
        os.mkdir(os.getcwd() +'/reports/')

    ##### Find Files #####
    mypath = os.path.abspath(os.getcwd())
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

    #main loop for all the malware on folder
    for malware in onlyfiles:
        logging.info("[*] Analyzing: " + malware)
        try:
            fp= open(malware)
            fp.close()
            key="" # <= Here Enter Your VT API Key between double quotes
            # define the name of the directory to be created
            path = os.getcwd() +'/reports/' + malware
            try:
                os.mkdir(path)
            except OSError:
                logging.error("[*]Creation of the directory failed")
            else:
                logging.info("[*]Successfully created the directory ")

            #PE analysis
            report_path = path + '/' + "PE Analysis"
        #    Basic_analysis(malware,report_path)
        #    PE_analysis(malware,report_path)

            #Strings Analysis
            report_path = path + '/' + "strings"
            md5_hash = Strings_analysis(malware,report_path)

            #Virustotal analysis
            report_path = path + '/' + "report.json"
            virustotaljson = report_path
            time.sleep(20)
            logging.info("[*]Waiting 20 sec for next request ")
            VT_Request(key, md5_hash.rstrip() , report_path , malware)

            #Avclass
            report_path = path + '/' + "avscan.json"
            logging.info("[*]AVRscan starting ")
            avclass(virustotaljson,report_path)
        except IOError:
            logging.error( "\n [-] There is a no file like '")
            continue

if __name__ == '__main__':
	main()
