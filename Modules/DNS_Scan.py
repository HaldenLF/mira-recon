import dns.resolver

def DNS_Scan(target, record_types):
    # Create a DNS resolver
    resolver = dns.resolver.Resolver()
    results = {}
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(target, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = "No record found"
        except dns.resolver.NXDOMAIN:
            results[record_type] = "Domain does not exist"
        except Exception as e:
            results[record_type] = f"Error: {e}"

    return results
               
# Set the target domain and record type
target = "example.com"
record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

# Print the results
for record_type, records in DNS_Scan(target, record_types).items():
    print(f"{record_type} records for {target}:")
    if isinstance(records, list):
        for record in records:
            print(f"  {record}")
    else:
        print(f"  {records}")