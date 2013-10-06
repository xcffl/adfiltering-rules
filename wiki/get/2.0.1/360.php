<?php

function downfile($fileurl)
{
$filename=$fileurl;
$file   =   fopen($filename, "rb");
Header( "Content-type:   application/gzip ");
Header( "Accept-Ranges:   bytes ");
Header( "Content-Disposition:   attachment;   filename= rules_for_360.xml.zip");


$contents = "";
while (!feof($file)) {
  $contents .= fread($file, 8192);
}
echo $contents;
fclose($file);

}
$url="http://rules.wd.360.cn/tmpdata/rule.php?id=60546";
downfile($url);

?>