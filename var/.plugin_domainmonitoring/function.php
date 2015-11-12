<?php

/*
 * Title: DomainMonitoring plugin.
 * Version: 1.0.1 (10/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com
 * Email: contact@montenegro-it.com
 */

class DomainMonitoring {

    static public function get_domainantizapret() {
        $blacklist = array();
        $domain = file("https://api.antizapret.info/group.php?data=domain&plugin=isp5lite", FILE_IGNORE_NEW_LINES);
        $server_domain = self::get_listdomain();
        $blacklist = array_intersect($domain, $server_domain);
        return $blacklist;
    }

    static public function get_ipantizapret() {
        $blacklist = array();
        $ip = file("https://api.antizapret.info/group.php?data=ip&plugin=isp5lite", FILE_IGNORE_NEW_LINES);
        $server_ip = self::get_serverip();
        $blacklist = array_intersect($ip, $server_ip);
        return $blacklist;
    }

    static public function check_block() {
        $data = array();
        $data['ip'] = self::get_ipantizapret();
        $data['domain'] = self::get_domainantizapret();
        return $data;
    }

    static public function get_spambase() {
        return array("zen.spamhaus.org", "cbl.abuseat.org", "bl.spamcop.net");
    }

    static public function send_mail($to, $from, $message) {
        foreach ($to as $mail) {
            $headers = array();
            $subject = "DomainMonitoring report";
            $headers[] = "MIME-Version: 1.0";
            $headers[] = "Content-type: text/plain; charset=utf-8";
            $headers[] = "From: " . $from . " <" . $from . ">";
            $headers[] = "Reply-To: " . $from . " <" . $from . ">";
            $headers[] = "Subject: {$subject}";
            mail($mail, $subject, $message, implode("\r\n", $headers));
            unset($headers);
        }
    }

    static public function cron_run() {
        $config = self::get_config();
        $message_antizapret = "";
        $message_spam = "";
        $message = "";
        $count_spam = 0;
        $count_item = 0;
        $count_antizapret = 0;
        if ($config['action']) {
            foreach (self::full_scan($config['action']) as $key => $row) {
                switch ($key) {
                    case "antizapret":
                        $message_antizapret = "\n\nantizapret block is:\n";
                        foreach ($row['domain'] AS $item) {
                            $count_antizapret++;
                            $count_item++;
                            $message_antizapret.=$item . "\n";
                        }
                        foreach ($row['ip'] AS $item) {
                            $count_antizapret++;
                            $count_item++;
                            $message_antizapret.=$item . "\n";
                        }
                        break;
                    case "spam":
                        if (!isset($row['server'])) {
                            break;
                        }
                        $message_spam.="\n\nspam block is:\n";
                        foreach ($row['server'] AS $id => $item) {
                            $count_spam++;
                            $count_item++;
                            $message_spam.=$row['ip'][$id] . " on " . $item . "\n";
                        }
                        break;
                }
            }
            if ($count_spam > 0) {
                $message.=$message_spam;
            }
            if ($count_antizapret > 0) {
                $message.=$message_antizapret;
            }

            $hash = md5($message);
            if ($config['hash'] == $hash || $count_item == 0) {
                return;
            } else {
                self::send_mail($config['to'], $config['from'], $message);
                file_put_contents(PLUGIN_PATH . ".lock", $hash);
            }
        }
    }

    static public function save_setting($from, $email, $spam, $antizapret) {
        $tmp_email = explode(",", $email);
        $email_array = array();
        foreach ($tmp_email AS $row) {
            if (filter_var(trim($row), FILTER_VALIDATE_EMAIL)) {
                $email_array[] = trim($row);
            }
        }
        if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
            $from = "root@" . php_uname('n');
        }
        $data['from'] = $from;
        $data['email'] = $email_array;
        $data['spam'] = $spam;
        $data['antizapret'] = $antizapret;
        file_put_contents(PLUGIN_PATH . "setting.txt", json_encode($data));
        chmod(PLUGIN_PATH . "setting.txt", 0600);
    }

    static public function get_config() {
        $file = file_get_contents(PLUGIN_PATH . "setting.txt");
        if ($file) {
            $param = json_decode($file);

            $spam = 0;
            $antizapret = 0;
            if ($param->spam=="on") {
                $spam = 1;
            }
            if ($param->antizapret=="on") {
                $antizapret = 1;
            }
            if ($antizapret && $spam) {
                $data['action'] = 'both';
            } elseif ($antizapret && !$spam) {
                $data['action'] = 'antizapret';
            } elseif (!$antizapret && $spam) {
                $data['action'] = 'spam';
            } else {
                $data['action'] = 0;
            }
            $data['from'] = $param->from;
            $data['to'] = $param->email;
            $data['hash'] = @file_get_contents(PLUGIN_PATH . ".lock");
        } else {
            $data['action'] = 0;
        }
        return $data;
    }

    static public function full_scan($type = 'none') {
        $data = array();
        switch ($type) {
            case "both":
                $antizapret = self::check_block();
                $data['antizapret']['ip'] = $antizapret['ip'];
                $data['antizapret']['domain'] = $antizapret['domain'];
                $data['spam'] = self::start_check();
                break;
            case "spam":
                $data['spam'] = self::start_check();
                break;
            case "antizapret":
                $antizapret = self::check_block();
                $data['antizapret']['ip'] = $antizapret['ip'];
                $data['antizapret']['domain'] = $antizapret['domain'];
                break;
            default:
        }
        return $data;
    }

    static public function start_check() {
        $ip = self::get_serverip();
        $data = self::check_base($ip);
        return self::filter_server($data);
    }

    static public function check_base($ip_array) {
        $data = array();
        ob_start();
        foreach ($ip_array as $row) {
            $revert = explode(".", $row);
            $ip = $revert[3] . "." . $revert[2] . "." . $revert[1] . "." . $revert[0];

            foreach (self::get_spambase() AS $base) {
                exec("host -tA " . $ip . "." . $base, $data['string']);
                $data['server'][] = $base;
                $data['ip'][] = $row;
            }
        }
        ob_end_clean();
        return $data;
    }

    static public function check_cron() {
        if (!is_file('/etc/cron.d/domainmonitoring')) {
            $data = "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n";
            $data.="15 * * * * root /usr/local/mgr5/addondomainmonitoring.cron.php  >/dev/null 2>&1\n\n";
            file_put_contents('/etc/cron.d/domainmonitoring', $data);
        }
    }

    static public function filter_server($server_array) {
        $search_string = "has address";
//for debug                 $search_string = "not found";
        $server = array();
        foreach ($server_array['string'] as $key => $row) {
            $pos = strpos($row, $search_string);
            if ($pos !== false) {
                $server['string'][] = $row;
                $server['ip'][] = $server_array['ip'][$key];
                $server['server'][] = $server_array['server'][$key];
            }
        }
        return $server;
    }

    static public function get_listdomain() {
        $domain = array();
        ob_start();
        exec("/usr/local/mgr5/sbin/mgrctl -m ispmgr domain", $data);
        ob_end_clean();
        foreach ($data as $row) {
            preg_match('/^name=(.*)displayname=/', $row, $matches, PREG_OFFSET_CAPTURE);
            $domain[] = trim($matches[1][0]);
        }
        return $domain;
    }

    static public function get_serverip() {
        $data = array();
        ob_start();
        exec('ifconfig |grep -v lo | grep -v 127.0.0 | awk \'/flags/ {printf "Interface "$1" "} /inet/ {printf $2" "} /status/ {printf $2"\n"}\'|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"', $data);
        $return = ob_get_contents();
        ob_end_clean();
        if ($return == 0) {
            //for debug   return array('8.8.8.8', '4.4.4.4', '66.44.11.99');
            return array_unique($data);
        } else {
            return false;
        }
    }

}
