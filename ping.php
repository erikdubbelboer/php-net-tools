#!/usr/bin/php
<?


// See: http://en.wikipedia.org/wiki/Ping


define('MICROSECOND', 1000000); // 1 second in microseconds


function checksum($data) {
  $bit = unpack('n*', $data);
  $sum = array_sum($bit);

  if (strlen($data) % 2) {
    $temp = unpack('C*', $data[strlen($data) - 1]);
    $sum += $temp[1];
  }

  $sum  = ($sum >> 16) + ($sum & 0xffff);
  $sum += ($sum >> 16);

  return pack('n*', ~$sum);
}




if (!isset($argv[1])) {
  die("usage: ping.php [-n] destination\n");
}

$host  = end($argv); // Destination should always be the last argument.
$names = !in_array('-n', $argv); // Print hostnames or ip's.

// Is it an IP or hostname?
if (long2ip(ip2long($host)) === $host) {
  $ip = $host;
} else {
  $ip = gethostbyname($host);

  if ($ip === $host) {
    die("invalid destination: $host\n");
  }
}


$sock = @socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp'));

if ($sock === false) {
  die("Failed to create raw socket. Make sure you run this as root\n");
}


$send     = 0;
$received = 0;

// This is needed for the signal handling to work.
declare(ticks = 1);

function sighandler($signal) {
  global $send, $received;

  $loss  = $send - $received;
  $lossp = round($loss / ($send / 100), 2);

  echo "\nsend:     $send" , 
       "\nreceived: $received" ,
       "\nloss:     $loss ($lossp%)\n";
  die;
}

pcntl_signal(SIGTERM, 'sighandler');
pcntl_signal(SIGHUP, 'sighandler');
pcntl_signal(SIGINT, 'sighandler');


if ($names) {
  $host = gethostbyaddr($ip);
}

echo "PING $host ($ip)\n";

$id  = rand(0, 0xFFFF);
$seq = 1;

for (;;) {
  $packet = '';
  $packet .= chr(8); // Type
  $packet .= chr(0); // Code
  $packet .= chr(0); // Header Checksum
  $packet .= chr(0);
  $packet .= chr($id & 0xFF); // Identifier
  $packet .= chr($id >> 8  );
  $packet .= chr($seq & 0xFF); // Sequence Number
  $packet .= chr($seq >> 8  );

  for ($i = 0; $i < 56; ++$i) { // Add 56 bytes of data
    $packet .= chr(0);
  }

  $checksum = checksum($packet);

  $packet[2] = $checksum[0];
  $packet[3] = $checksum[1];
  
  $start   = microtime(true) * MICROSECOND;
  $timeout = $start + MICROSECOND;
  
  socket_sendto($sock, $packet, strlen($packet), 0, $ip, 0); // ICMP doesn't have a port so just use 0

  ++$send;

  for (;;) {
    $now = microtime(true) * MICROSECOND;

    if ($now >= $timeout) {
      echo " *\n";
      break;
    }

    $read  = array($sock);
    $other = array();

    $selected = socket_select($read, $other, $other, 0, $timeout - $now);

    if ($selected === 0) {
      echo " *\n";
      break;
    } else {
      socket_recvfrom($sock, $data, 65535, 0, $rip, $rport);

      $data = unpack('C*', $data);

      // Is this our packet?
      if (($data[10] == 1) && // ICMP
          ($data[21] == 0) && // ICMP response
          ($data[25] == ($id & 0xFF)) &&
          ($data[26] == ($id >> 8))   &&
          ($data[27] == ($seq & 0xFF)) &&
          ($data[28] == ($seq >> 8))) {
        if ($names) {
          $rip = gethostbyaddr($rip);
        }
        
        $now  = microtime(true) * MICROSECOND;
        $time = round(($now - $start) / 1000, 2); // ms

        echo (count($data) - 20) , " bytes from $rip seq=$seq time=$time ms\n"; // the header is 20 bytes

        ++$received;

        break;
      }
    }
  }

  sleep(1);

  ++$seq;
}

