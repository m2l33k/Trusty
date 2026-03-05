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
            var dirInfo = new DirectoryInfo(dirPath);
            var acl = dirInfo.GetAccessControl();
            acl.SetAccessRuleProtection(true, false);
            
            var existingRules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in existingRules) acl.RemoveAccessRule(rule);
            
            var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            acl.AddAccessRule(new FileSystemAccessRule(everyoneSid, FileSystemRights.Read | FileSystemRights.ListDirectory, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Deny));
            
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            acl.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            
            acl.SetOwner(systemSid);
            dirInfo.SetAccessControl(acl);
            Console.WriteLine("Success!");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }
    }
}
