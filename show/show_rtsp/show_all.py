"""show all the cameras in the file"""
import os
import sys

cwd = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(cwd, '../..'))
from utils.base import printf


file = sys.argv[1]  # should in format (ip,user,pass) or (ip,cve-2017-7921)
with open(file, 'r') as f:
    items = [line.strip().split(',') for line in f if line.strip()]


items = [i for i in items if i[-2] == 'Dahua' or i[-2] == 'Hikvision']
items = [i for i in items if i[2] or i[-1] == 'cve-2017-7921']

print()
printf(f"there are {len(items)} cameras in file {file}", color='blue', bold=True, flash=True)
printf("input any key to get another gruop cameras")
printf("input q to quit this program")
printf("before get another groups, you should place your mouse over the camera "
       "and press q to exit the current camera", color='red', bold=True)
print()


# do not set the rows and cols too big, since the network equality
height = 200
rows, cols = 2, 3

while items:
    y = 0
    for row in range(rows):
        x = 0
        for col in range(cols):
            if items:
                cam = items.pop()
                if cam[-1] == 'cve-2017-7921':
                    os.system(f"python3 -Bu {os.path.join(cwd, 'show_cve_2017_7921.py')} "
                            f" --ip {cam[0]} --x {x} --y {y} --height {height}&")
                else:
                    os.system(f"python3 -Bu {os.path.join(cwd, 'show_one_camera.py')} "
                            f" --ip {cam[0]} --user {cam[2]} --passwd {cam[3]} --x {x} --y {y} --height {height}&")
            else:
                break
            x += 360
        y += height + 35
    if input().strip() == 'q': break