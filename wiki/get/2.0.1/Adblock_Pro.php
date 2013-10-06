<?php

function downfile($fileurl)
{
$filename=$fileurl;
$file   =   fopen($filename, "rb");
Header( "Content-type:   application/ini ");
Header( "Accept-Ranges:   bytes ");
Header( "Content-Disposition:   attachment;   filename= rules_for_AB_PRO.ini");


$contents = "";
while (!feof($file)) {
  $contents .= fread($file, 8192);
}
echo $contents;
fclose($file);

}
$url="http://adfiltering-rules.googlecode.com/svn/trunk/lastest/rules_for_AB_PRO.ini";
downfile($url);

?>