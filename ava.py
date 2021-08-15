import json
import sys
if len(sys.argv) != 3:
    print("Syntax: avclass_converter.py [inputfile] [outputfile]")
    sys.exit(1)
with open(sys.argv[1]) as f:
    lines = f.readlines()
with open(sys.argv[2], "w") as f:
    for line in lines:
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

        res = {"md5": md5, "sha256": sha256, "sha1": sha1,
               "first_seen": first_seen, "scan_date": scan_date, "av_labels": av_labels}

        f.write(json.dumps(res) + "\n")
