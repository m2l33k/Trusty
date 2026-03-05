using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class Program
{
    static void Main()
    {
        try
        {
            var dirPath = @"C:\Users\m2l3k\Desktop\testprotection";
            if (!Directory.Exists(dirPath)) Directory.CreateDirectory(dirPath);
            File.WriteAllText(Path.Combine(dirPath, "api_key.txt"), "API_KEY=sk_live_1234");
            
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            
            // Directory
            var dirInfo = new DirectoryInfo(dirPath);
            var dacl = dirInfo.GetAccessControl();
            dacl.SetAccessRuleProtection(true, false);
            foreach (FileSystemAccessRule r in dacl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                dacl.RemoveAccessRule(r);
            dacl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            dirInfo.SetAccessControl(dacl);
            
            // File
            var filePaths = Directory.GetFiles(dirPath);
            foreach (var f in filePaths) {
                var finfo = new FileInfo(f);
                var facl = finfo.GetAccessControl();
                facl.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule r in facl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    facl.RemoveAccessRule(r);
                facl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                finfo.SetAccessControl(facl);
            }
            
            Console.WriteLine("SUCCESS_LOCKDOWN");
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAIL_LOCKDOWN: " + ex.Message);
        }
    }
}
