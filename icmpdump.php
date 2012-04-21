#!/usr/bin/php
<?

// From: http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
$icmp_types = array(
  array(
    'Echo Reply',
    array(
      'Echo reply'
    )
  ),

  array(
    'Reserved',
    array(
      'Reserved'
    )
  ),

  array(
    'Reserved',
    array(
      'Reserved'
    )
  ),

  array(
    'Destination Unreachable',
    array(
      'Destination network unreachable',
      'Destination host unreachable',
      'Destination protocol unreachable',
      'Destination port unreachable',
      'Fragmentation required',
      'Source route failed',
      'Destination network unknown',
      'Destination host unknown',
      'Source host isolated',
      'Network administratively prohibited',
      'Host administratively prohibited',
      'Network unreachable for TOS',
      'Host unreachable for TOS',
      'Communication administratively prohibited',
      'Host Precedence Violation',
      'Precedence cutoff in effect'
    )
  ),

  array(
    'Source Quench',
    array(
      'Source quench (congestion control)'
    )
  ),

  array(
    'Redirect Message',
    array(
      'Redirect Datagram for the Network',
      'Redirect Datagram for the Host',
      'Redirect Datagram for the TOS & network',
      'Redirect Datagram for the TOS & host'
    )
  ),

  array(
    '',
    array(
      'Alternate Host Address'
    )
  ),

  array(
    '',
    array(
      'Reserved'
    )
  ),

  array(
    'Echo Request',
    array(
      'Echo request (used to ping)'
    )
  ),

  array(
    'Router Advertisement',
    array(
      'Router Advertisement'
    )
  ),

  array(
    'Router Solicitation',
    array(
      'Router discovery/selection/solicitation'
    )
  ),

  array(
    'Time Exceeded',
    array(
      'TTL expired in transit',
      'Fragment reassembly time exceeded',
    )
  ),

  array(
    'Parameter Problem: Bad IP header',
    array(
      'Pointer indicates the error',
      'Missing a required option',
      'Bad length'
    )
  ),

  array(
    'Timestamp',
    array(
      'Timestamp'
    )
  ),

  array(
    'Timestamp reply',
    array(
      'Timestamp reply'
    )
  ),

  array(
    'Information Request',
    array(
      'Information Request'
    )
  ),

  array(
    'Information Reply',
    array(
      'Information Reply'
    )
  ),

  array(
    'Address Mask Request',
    array(
      'Address Mask Request'
    )
  ),

  array(
    'Address Mask Reply',
    array(
      'Address Mask Reply'
    )
  )

  // ...
);


// From: http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
$protocols = array(
  1  => 'ICMP',

  // ...

  6  => 'TCP',

  // ...
  
  17 => 'UDP'

  // ...
);


function ip($data, $at) {
  return $data[$at+0] . '.' .
         $data[$at+1] . '.' .
         $data[$at+2] . '.' .
         $data[$at+3];
}


function info_icmp($data) {
  global $icmp_types;

  echo ' type=[';

  if (!isset($icmp_types[$data[0]])) {
    echo 'unknown(' , $data[0] , ')]';
    return;
  }

  $type = $icmp_types[$data[0]];

  echo $type[0] , '] code=[';

  if (!isset($type[1][$data[1]])) {
    echo 'unknown(' , $data[1] , ')]';
    return;
  }

  echo $type[1][$data[1]] , ']';
}


function info_udp($data) {
  // Convert to bytes to a short
  $port = pack('C*', $data[0], $data[1]);
  $port = unpack('n*', $port);
  echo ' sourceport=' , $port[1];
  
  // Convert to bytes to a short
  $port = pack('C*', $data[2], $data[3]);
  $port = unpack('n*', $port);
  echo ' destinationport=' , $port[1];
}


function info_tcp($data) {
}


function info($data, $top) {
  global $protocols;
  
  echo ' ' , ip($data, 12) , ' > ' , ip($data, 16), ' protocol=';
   
  if (!isset($protocols[$data[9]])) { 
    echo 'unknown(' , $data[9], ')';
    return;
  }

  echo $protocols[$data[9]];

  if ($data[9] == 1) { // ICMP
    info_icmp(array_slice($data, 20));

    if (($data[9] == 1) && ($data[20] == 3)) { // ICMP Destination Unreachable
      echo "\n\tdata: ";

      // Print into on the contained packet
      info(array_slice($data, 28), false);
    }
  } else if ($data[9] == 6) { // TCP
    info_tcp(array_slice($data, 20));
  } else if ($data[9] == 17) { // UDP
    info_udp(array_slice($data, 20));
  }
}



$sock = @socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp'));

if ($sock === false) {
  die("failed to create raw socket\nmake sure you run this as root\n");
}

$packets = 0;

// This is needed for the signal handling to work.
declare(ticks = 1);

function sighandler($signal) {
  global $packets;

  die("\n\npackets: $packets\n");
}

pcntl_signal(SIGTERM, 'sighandler');
pcntl_signal(SIGHUP, 'sighandler');
pcntl_signal(SIGINT, 'sighandler');

echo "icmpdump started\n";

for (;;) {
  $read  = array($sock);
  $other = array();

  @socket_select($read, $other, $other, null);

  socket_recvfrom($sock, $data, 65535, 0, $ip, $port);

  ++$packets;

  echo date('h:i:s');

  $data = unpack('C*', $data);

  // unpack returns an array starting at index 1, make it start at index 0
  $data = array_values($data);

  info($data, true);

  echo "\n";
}

