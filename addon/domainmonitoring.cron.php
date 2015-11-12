#!/usr/bin/php
<?php
/*
 * Title: DomainMonitoring plugin for ispmanager 5.
 * Version: 1.0.0 (12/Nov/2015)
 * Author: Denis.
 * License: GPL.
 * Site: https://montenegro-it.com
 * Email: contact@montenegro-it.com
 */
@set_time_limit(0);
@error_reporting(E_NONE);
@ini_set('display_errors', 0);
define("PLUGIN_PATH", "/usr/local/mgr5/var/.plugin_domainmonitoring/");
include_once (PLUGIN_PATH."function.php");
DomainMonitoring::cron_run();