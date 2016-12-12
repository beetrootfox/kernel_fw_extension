#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH "/proc/firewallExtension"

unsigned long size = 2048;
char* ruleset;

int read_rules(char* fname){
	int c, i, tmp;
	ruleset = malloc(sizeof(char) * size);
	if(!ruleset){
		perror("Malloc failed");
		exit(-1);
	}
	FILE *fp;
	fp = fopen(fname, "r");
	if(!fp){
		perror("ERROR: Cannot open file");
		exit(-1);
	}
	i = 0;
	while(1){
	while((c = getc(fp)) != EOF && c != ' ' && c != '\n'){
		if(i >= size){
			ruleset = realloc(ruleset, size * 1.5);
			if(!ruleset){
				perror("ERROR: ruleset is too long");
				exit(-1);
			}
			size *= 1.5; 
		}
		ruleset[i] = c;
		i++;
	}
	if(c == EOF && ruleset[i-1] != '\n'){
		perror("ERROR: Ill-formed file");
		exit(-1);
	}
	if(c == EOF){
		ruleset[i-1] = '\0';
		fclose(fp);
		return i;
	}
	ruleset[i] = c;
	i++;
	tmp = i;
	while((c = getc(fp)) != EOF && c != '\n'){
		if(i >= size){
			ruleset = realloc(ruleset, size * 1.5);
                        if(!ruleset){
                                perror("ERROR: ruleset is too long");
                                exit(-1);
                        }
                        size *= 1.5;
		}
		ruleset[i] = c;
		i++;
	}
	if(c == EOF){
		perror("ERROR: Ill-formed file");
		exit(-1);
	}
	ruleset[i] = '\0';
	struct stat s;
	if(!stat(ruleset + tmp, &s)){
		if(!(S_ISREG(s.st_mode) && s.st_mode & 0111)){
			perror("ERROR: Cannot execute file");
			exit(-1);
		}

	}else{
		perror("ERROR: Ill-formed file");
		exit(-1);
	}
	ruleset[i] = c;
	i++;
	}
}

int main(int argc, char *argv[])
{

    
	int option = 0; 
	if(argc <2)
	{
		printf("Usage:\n");
		printf(" %s L            to display rules in kern.log\n", argv[0]);
		printf(" %s W <filename> to load new rules\n", argv[0]);
		return 1;
	}
	else {
		if(strcmp(argv[1],"L")==0){
			printf("Print current policy\n");
			// TODO: Complete me
			char command[10 + sizeof(PATH)];
			snprintf(command, sizeof(command), "echo L > %s", PATH);
			system(command);
			return 0;
		} else {
			if(strcmp(argv[1],"W")==0){
				printf("Reading commands\n");
				read_rules(argv[2]);
				char command[10 + sizeof(PATH) + size];
				snprintf(command, sizeof(command), "echo \"W %s\" > %s",
						ruleset, PATH);
				system(command);
				return 0;
			} else{
				printf("Usage:\n ");
				printf("+L to display rules in kern.log\n");
				printf("+\n");
				printf("%s",argv[1]);
				return 1;
			}
		}
	}
}
