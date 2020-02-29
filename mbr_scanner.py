import hashlib, sys, binascii, struct

# Function to convert little endian stored values to big endian
def little_big_endian(le_value):
	# Convert to byte array
	le_bytes = bytearray.fromhex(le_value)
	# Reverse the bytes (each 2 hex characters)
	le_bytes.reverse()
	# Join the values while interpretting them
	be_value = ''.join(format(x, '02x') for x in le_bytes)
	# Calculate the decimal value
	decimal_value = int(be_value, 16)
	return be_value, decimal_value

# Function to retrieve the hex properties of the partition based on the MBR record
def partition_decode(sector):
	# Substring extraction to could through the 32 character hex value and separate the important data
	# Makes use of the little_big_endian function to create a big endian and decimal formatted output
	status = sector[:2]
	chs_first = 'Little Endian: ' + sector[2:-24] + \
	'\t\tBig Endian: ' + little_big_endian(sector[2:-24])[0] + \
	' \tDecimal Value: ' + str(little_big_endian(sector[2:-24])[1])
	
	partition_type = sector[8:-22]
	
	chs_last = 'Little Endian: ' + sector[10:-16] + \
	'\t\tBig Endian: ' + little_big_endian(sector[10:-16])[0] + \
	' \tDecimal Value: ' + str(little_big_endian(sector[10:-16])[1])

	lba_first = 'Little Endian: ' + sector[16:-8]  + \
	'\t\tBig Endian: ' + little_big_endian(sector[16:-8])[0] + \
	' \tDecimal Value: ' + str(little_big_endian(sector[16:-8])[1])

	sector_count_output = 'Little Endian: ' + sector[24:] + \
	'\t\tBig Endian: ' + little_big_endian(sector[24:])[0] + \
	'\tDecimal Value: ' + str(little_big_endian(sector[24:])[1])
	
	# Calculation of the partition size based on the sector count and 512B/sector
	sector_count = sector[24:]
	sector_count_decimal = little_big_endian(sector_count)[1]
	partition_size = (512 * sector_count_decimal)/(2**10)**2

	# Return all values as a list
	return [status,chs_first,partition_type,chs_last,lba_first,sector_count_output, partition_size]

# Main function for user io
def main():
	print('\n******************** Austin Jansz\'s MBR Scanner********************')
	# Save MBR and hash the 
	# Get the image file from the python parameters as well as define a name for the output file
	img_filename = str(sys.argv[1])
	mbr_filename = img_filename + '.mbr'
	# Read the first 512 B of the image file (MBR sector)
	with open(img_filename, 'rb') as f:
		mbr = f.read(512)
		f.close()
	# Copy the MBR data to the MBR output file
	with open(mbr_filename, 'w') as f:
		f.write(mbr)
		f.close()
	# Confirm with the user and output the hashing data
	print('MBR data was saved to the file: ' + mbr_filename)
	print('SHA256 hash: ' + hashlib.sha256(mbr).hexdigest())
	
	# Get statistics on the partitions based on 
	# Check for which partition the user would like to process
	partition_offset = input('Partition number [1..4]: ')
	# Read the partition MBR data using the partition offset value
	with open(img_filename, 'rb') as f:
		f.seek(446 + (partition_offset-1)*16)
		partition_raw = f.read(16)
		f.close()
	# Convert the binary data to ascii string hex values
	partition = binascii.b2a_hex(partition_raw)
	# Process the data to get a full list of the values
	partition_layout = ['Status','Frist CHS','Type','Last CHS','First LBA','Sectors','Size [MB]']
	partition_stats = partition_decode(partition)
	# Nicely output the data for the user to see
	i = 0
	while i<len(partition_stats):
		seperator = ':\t'
		if len(partition_layout[i]) < 7:
			seperator = ':\t\t'
		print(partition_layout[i] + seperator + str(partition_stats[i]))
		i += 1

	# Save a partition and hash the 
	# Define filename for the saving of the partition data
	partition_filename = img_filename + '.partition-'+str(partition_offset)
	# Get the decimal value of the LBA start address
	partition_start_address = little_big_endian(partition[16:-8])[1]
	# Get the decimal number of sectors for the partition
	partition_sectors = little_big_endian(partition[24:])[1]
	# Read the image file
	with open(img_filename, 'rb') as f:
		# Set the offset to the LBA start address
		f.seek(partition_start_address)
		# Read the sectors of data (512 B / sector)
		partition_data = f.read(partition_sectors*512)
		f.close()
	# Write the data to the partition file
	with open(partition_filename, 'w') as f:
		f.write(partition_data)
		f.close()
	# Read the file byte by byte
	with open(partition_filename, 'rb') as f:
		partition_bytes = f.read()
		f.close()
	# Confirm with the user the save location and the file hash
	print('Partition data was saved to the file: ' + partition_filename)
	print('SHA256 hash: ' + hashlib.sha256(partition_bytes).hexdigest())
	print('\n\n')
main()