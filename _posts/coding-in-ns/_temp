# Coding in NS
I am currently stuck in camp, and the _urge_ just hit me... I can't resist...

The urge to code of course! I have too many ideas swimming in my head, just waiting to be implemented. I can't wait till weekends :angry:! So, what to do?

Well, it's not like the situation is completely hopeless. Assuming you have a Learnet tablet, or even just your mobile phone (with some accessories), it should be possible to have a suitable development environment for your code, for free. 

## What can we even do? 
The Learnet tablet is a sleek, tiny tablet that has Windows 10 installed on it. You do not have admin rights, nor are you allowed to download any apps, games or tools. Microsoft Edge and Chrome browsers are pre-installed. Certain sites are blocked, including Github (but not Gitlab/BitBucket etc).

Whatever approaches we use, they must be web-based, and should not require a Github login. 

After some research, I have collected a few approaches to the problem, along with their specific use-cases. What kind of project you are working on, and the tools you need, of course, do affect the feasibility of the different approaches. Some of the approaches assume you have the technical knowledge necessary to understand what's happening behind scenes.

## Apache Guacamole
If you are developing a GUI app that runs on desktop, or need specific tools that cannot be emulated or made available over the web, you will need to resort to this. 

Apache Guacamole is basically RDP but in a website, and doesn't get blocked by the Learnet internet.


## Visual Studio Online

## Cloud IDEs
The point of these IDEs is to develop and publish an application using cloud platform tools, usually a web application. All of them of excellent type-hinting support and even go so far as giving you a shell to run commands.

### [codeanywhere](https://codeanywhere.com/) (Free for 7 days only)
![Codeanywhere](https://lh3.googleusercontent.com/MiNCWaHQQFug6H38D_Xpcm134PA2UcPXI2UFPqzLenEXjB-AgvvogxMCfKlmTtRG6cN4ZbXM=w640-h400-e365)

Of the bunch, `codeanywhere` is probably the best due to its better interface and better type-hinting. However, it is paid, and even the free trial is only for 7 days.

### [codenvy](https://codenvy.com/) / [Eclipse Che](https://www.eclipse.org/che/)
![Eclipse Che 7](https://miro.medium.com/max/1600/1*GfVJwEqhMUxMOskIs1Iqcw.png)

`codeenvy`/`Eclipse Che` are actually almost the same (`codeenvy` is build on the work of `Eclipse Che`). Currently, `Eclipse Che` is better since it uses `theia` as the editor, while `codeenvy` is still using a older one. The picture above is of `Eclipse Che`, for your reference.

### Others
e.g. [StackBlitz](https://stackblitz.com/) for Angular/React


## [code-server](https://github.com/cdr/code-server)
// TODO make this into actual instructions
If you want a IDE that is fully customizable and gives you full control of the underlying machine, you can use `code-server`. It's basically a instance of Visual Studio in the cloud, and you can even install plugins to support other languages and tools (you can even code in Rust if you want, all with type-hinting Intellisense). You will have to provision your own cloud virtual machine, or make one of your machines at home available online first. The former is preferred due to its simpler nature.

1. [Setup a Google Compute Engine instance](https://cloud.google.com/compute/docs/instances/create-start-instance). An Ubuntu VM in the `asia-southeast1-b` area is best.
1a. (Optional) Setup CNAME and setup Static IP Address // TODO
2. Download the [code-server binary](https://github.com/cdr/code-server#binaries).
3. Run `code-server -p 443`.
4. Open up `<ip>:443/` in your browser and enjoy.


## SSH to Desktop/SSH to Cloud
sqs.io
Google Cloud Shell


## For experiments
1. CodeSandbox
2. CodePen
3. JSFiddle
3. repl.it
