#/usr/bin/python
import sys, subprocess

num_try = 1
frontends = {}

if __name__ == "__main__":

	# Run frontends
	for i in range(num_try):
		p = subprocess.Popen("pkgmgr_frontend_test -n 2>/dev/null 1>/dev/null".split())
		frontends[i] = p
		print("Run %d/%d frontend"%(i, num_try))


	# wait frontends to be end
	done = {}
	seq = []
	while True:
		for i in frontends:
			if not done.has_key(i):
				p = frontends[i]
				ret = p.poll()
				if not None == ret:
						print("Frontend #%d is terminated. Returns: %d"%(i, -ret))
						done[i] = -ret
						seq.append(i)
		if num_try == len(done):
			break
	
	print("Test done.")
	for i in frontends:
		print("Return code of frontend #%d = %d"%(i, done[i]))
	#print("Terminate seq:")
	#print(seq)

