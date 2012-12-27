#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

void attach(pid_t pid) {
	int stat;
	
	printf("attach\n");

	printf("Attaching to PID %u\n", pid);
	if(ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
		err(EXIT_FAILURE, "ptrace (ATTACH)");

	waitpid(pid, &stat, 0);
}

void detach(pid_t pid) {
	printf("detach\n");

	printf("Detaching from PID %u\n", pid);
	if(ptrace(PTRACE_DETACH, pid, 0, 0) < 0)
		err(EXIT_FAILURE, "ptrace (DETACH)");
}

int get_heap_range(pid_t pid, void **addr_start, void **addr_end) {
	int ret = -1;
	char buffer[2048], filename[1024], flags[32];

	sprintf(filename, "/proc/%u/maps", pid);

	FILE *file = fopen(filename, "r");
	
	if(!file)
		return -1;

	size_t offset, inode;
	unsigned dev_major, dev_minor;

	while(fgets(buffer, sizeof(buffer), file)) {
		sscanf(buffer, "%zx-%zx %31s %zx %x:%x %zu %1023s", (size_t *)addr_start, (size_t *)addr_end, flags, &offset, &dev_major, &dev_minor, &inode, filename);

		if(strcmp(filename, "[heap]") == 0) {
			ret = 0;
			break;
		}
	}

	fclose(file);

	return ret;
}

void scan_heap(pid_t pid, unsigned value, unsigned **map, size_t *length, size_t max_length) {
	long ret;
	void *addr, *addr_end;
	
	if(get_heap_range(pid, &addr, &addr_end) < 0)
		errx(EXIT_FAILURE, "Failed to get heap range\n");
	
	printf("Heap: 0x%016zx %.02f MiB\n", (size_t)addr, (double)(addr_end - addr) / 1024 / 1024);
	
	assert(sizeof(long) == 8);

	while(addr < addr_end) {
		errno = 0;

		ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if(errno) {
			err(EXIT_FAILURE, "ptrace (PEEKDATA)");
		}
		else {
			if(((ret >> 0) & 0x00000000ffffffff) == value)
				map[(*length)++] = addr + 0;

			if(*length >= max_length)
				errx(EXIT_FAILURE, "Max. length exceeded\n");

			if(((ret >> 4) & 0x00000000ffffffff) == value)
				map[(*length)++] = addr + 4;

			if(*length >= max_length)
				errx(EXIT_FAILURE, "Max. length exceeded\n");
		}

		addr += sizeof(long);
	}
}

void rescan_heap(pid_t pid, unsigned value, unsigned **map, size_t *length) {
	void *addr;
	long ret;
	unsigned offset;
	size_t new_length = 0, len = *length;

	for(size_t src = 0, dest = 0; src < len; ++src) {
		addr = (void *)((size_t)map[src] & ~(sizeof(long) - 1));
		offset = (size_t)map[src] & (sizeof(long) - 1);
		
		errno = 0;

		ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if(errno) {
			err(EXIT_FAILURE, "ptrace (PEEKDATA)");
		}
		else {
			if(((ret >> offset) & 0x00000000ffffffff) == value) {
				map[(*length)++] = addr + 0;
				map[dest++] = map[src];
				++new_length;
			}
		}
	}
	
	*length = new_length;
}

void write_heap(pid_t pid, unsigned value, unsigned *addr32) {
	void *addr;
	long ret;
	unsigned offset;

	addr = (void *)((size_t)addr32 & ~(sizeof(long) - 1));
	offset = (size_t)addr32 & (sizeof(long) - 1);
	
	errno = 0;

	ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if(errno) {
		err(EXIT_FAILURE, "ptrace (PEEKDATA)");
	}
	else {
		printf("Old value: 0x%016zx\n", ret);
		ret = ret & ~(0x00000000ffffffff << offset) | (value << offset);
		printf("New value: 0x%016zx\n\n", ret);

		if(ptrace(PTRACE_POKEDATA, pid, addr, ret) < 0)
			err(EXIT_FAILURE, "ptrace (POKEDATA)");
	}
}

int main(int argc, char **argv) {
	if(argc != 2)
		errx(EXIT_FAILURE, "missing argument");

	char *end = NULL;
	pid_t pid;
	size_t length = 0, max_length = 1024 * 1024;
	unsigned **map = malloc(sizeof(unsigned *) * max_length);
	unsigned value;
	
	errno = 0;
	pid = strtol(argv[1], &end, 10);
	if(errno)
		err(EXIT_FAILURE, "strtol");
	else if(argv[1] == end || *end)
		errx(EXIT_FAILURE, "strtol");

	printf("Enter current value: ");
	scanf("%u", &value);

	printf("Scanning memory for %u...\n", value);

	attach(pid);
	scan_heap(pid, value, map, &length, max_length);
	detach(pid);

	printf("Found %u %zu times.\n", value, length);
	
	for(; length > 1;) {
		printf("Enter current value: ");
		scanf("%u", &value);
		
		attach(pid);

		printf("Re-scanning memory for %u...\n", value);

		rescan_heap(pid, value, map, &length);
		
		printf("Found %u %zu times.\n", value, length);
		
		if(length == 1) {
			printf("Enter desired value: ");
			scanf("%u", &value);
			
			write_heap(pid, value, map[0]);
		}
		
		detach(pid);

		printf("\n");
	}

	return EXIT_SUCCESS;
}
