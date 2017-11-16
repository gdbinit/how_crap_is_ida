How crap is IDA?

An IDA plugin to compare IDA detected functions output versus LC_FUNCTION_STARTS information.

(c) fG!, 2017 - reverser@put.as - https://reverse.put.as



This is a basic IDA 7 (not compatible with earlier versions) plugin to compare LC_FUNCTION_STARTS information against functions discovered by IDA.

The LC_FUNCTION_STARTS command contains information about where each function in the binary starts, which is extremely useful information for reversing and debugging binaries.

What this plugin does is to extract that information and compare against functions discovered by IDA to understand if IDA missed any. One must be aware that information in LC_FUNCTION_STARTS can be easily manipulated so this assumes that the input binary hasn't been tampered with.

The use cases for this are probably small but I do have some, that's why I created it.

Be aware that parsing is very liberal and without error checking so you probably want to use it against non-malicious targets or just improve the code yourself. IDA tries to validate Mach-O binaries although it still has some bugs ;-).

To use this plugin you need to select manual load when loading a binary and load all segments/sections, __LINKEDIT in particular. By default IDA doesn't map this segment and it's needed to extract LC_FUNCTION_STARTS. Sucks, but that is what we have from IDA SDK!

