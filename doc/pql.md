# Introduction


# Language definition

## Arrays

``` 
select * from a where tcp[start:len] == [a0, b1, c2, d4]
select * from a where tcp[start:len] != [a0, b1, c2, d4]
select * from a where tcp[start] == a0

```
Extract from start len bytes. Operator == and array definition


## Bitshift

Size min of 2 max of 8
```
>>  Shift right
<<  Shift left 

```


tcp[n:2] >> nbits to usize
tcp[n:4] << nbits to usize
tcp[n:8] << nbits to usize


## Bitwise operator

tcp[n:2] & 0xff00
tcp[n:4] & 0xff000000
tcp[n:8] & 0xff000000ff000000

## Functions

fn name (p1, pn) -> result {
    
}

Example:

Return value: int, bool, array
fn name (ssh_sig: array) -> result {
    ssh_sig == [0x53, 0x53, 0x48, 0x2d]
}

In this case the return type is bool and the param type is array


## Packet

```
p = Packet {
    Eth {
        src: 00:65:a3:c8:89:27,
        dst:
    },
    IPv4 {
        dst: 192.168.3.123
    },
    Tcp {
        dst: 80,
        payload: [0xa1, 0xb2]
    }
}

response = send(p)
print(response)
```

## Examples

```
select ip.src, ip.dst
from a
where eth.src == 00:65:a3:c8:89:27 and
      ip.dst == 192.168.3.123 and
      tcp.dport == 443 or tcp.dport == 80 and
      tpc.payload[2:4] == [0x58, 0x58, 0x48 0x2d];

```
## Aggregate functions
### Sum

```
select sum(frame.origlen) 
from a
where tcp.port == HTTPS
interval now to now - 1h;
```