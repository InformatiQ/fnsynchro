import os, commands, logging, time
import re
import stat
from configobj import ConfigObj
from optparse import OptionParser

log = logging.getLogger("FNSynchro")
#hdlr = logging.FileHandler('/var/log/FNSynchro.log')
FORMAT='%(asctime)s\t%(levelname)s\t%(message)s'
formatter = logging.Formatter(FORMAT)
logging.basicConfig(format=FORMAT) # log sur console
#hdlr.setFormatter(formatter)
#log.addHandler(hdlr)
log.setLevel(logging.DEBUG) #set verbosity to show all messages of severity >= DEBUG

class initConfig:
    def parse_cli(self,argv):
        """ Commandline parser """
        parser = OptionParser(usage = '%prog [options]')
        # options
        parser.add_option('--config', type='string', dest='config', metavar='config',
               help='configuration, default=/etc/FNSynchro/FNSynchro.ini')

        parser.add_option('--object', type='string', dest='object', metavar='object',
               help='sync object, default=all')

        (opts, _) = parser.parse_args(argv)

        return opts

    def parse_ini(self, cfg_file='/etc/FNSynchro/FNSynchro.ini', object='all'):
        """
        This is the configuration parser, it parses /etc/FNSynchro/FNSynchro.ini or any other file passed to the cli.
        accepts
            cfg_file: file path of the INI file
        returns
            dict(foo): describing the backup objects 
        """
        config = ConfigObj(cfg_file)
        if object not in [ None, '', 'all']:
            sections = ['system','general', object]
        else:
            sections = config.sections
        foo = {}
        for section in sections:
            log.debug('section = %s' %section)
            bar = config[section]
            if section == 'system':
                global system
                system = {}
                for def_key in bar.iterkeys():
                    system[def_key] = bar.get(def_key)
            else:
                foo[section] = {}
                for key in bar.keys():
                    if key == 'pattern' :
                        log.debug('parsing pattern')
                        foo[section][key] = []
                        for pattern_item in bar.get(key).split('/'):
                            log.debug('parsing pattern item %s' %pattern_item)
                            if pattern_item.startswith('__'):
                                if not bar.get(pattern_item[2:]):
                                    foo[section][key].append(foo['general'][pattern_item[2:]])
                                else:
                                    foo[section][key].append(bar.get(pattern_item[2:]))
                            elif pattern_item.startswith(':'):
                                foo[section]['exceptions'] = []
                                for exception in bar.get(pattern_item[1:])['exceptions']:
                                    foo[section]['exceptions'].append(os.path.join(pattern_item[1:],exception))
                            else:
                                foo[section][key].append([pattern_item])
                    elif key in ['src', 'dst', 'base_src', 'base_dst']:
                        log.debug('parsing %s' %key)
                        path_value = ''
                        val = bar.get(key)
                        log.debug('key value is %s' %val)
                        for item in val.split('/'):
                            log.debug('going through %s' %item)
                            if item.startswith('__'):
                                log.debug('value is a reference to %s' %bar.get(item[2:]))
                                if not bar.get(item[2:]):
                                    log.debug('key reference not found in section, look at it in general')
                                    path_value = os.path.join(path_value,foo['general'][item[2:]])
                                else:
                                    path_value = os.path.join(path_value,bar.get(item[2:]))
                            else:
                                path_value = os.path.join(path_value,item)
                        log.debug('%s value is %s' %(key,path_value))
                        foo[section][key] = path_value
                    else:
                        foo[section][key] = []
                        for item in bar.get(key):
                            if item.startswith('__'):
                                if not bar.get(item[2:]):
                                    foo[section][key].append(foo['general'][pattern_item[2:]])
                                else:
                                    foo[section][key].append(bar.get(item[2:]))
                            else:
                                foo[section][key].append(item)
                        if section != 'general' and foo['general'].get(key):
                            foo[section][key].append(foo['general'][key])
                if section != 'general':
                    log.debug('appending general stuff')
                    for key in foo['general'].keys():
                        if foo[section].get(key):
                            log.debug('there is the same in that section, value from general will be appended')
                            foo[section][key].append(foo['general'][key])
                        else:
                            log.debug('only available in general')
                            foo[section][key] = foo['general'][key]
                            log.debug(foo[section][key])
        return foo

    def get_config(self, argv=None):
        options = self.parse_cli(argv)
        return self.parse_ini(options.config, options.object)

class lock:

    def __init__(self,system):
        self.lock_file = system['lock_file']
        self.wait_time = system['wait_time']
        self.wait_maxtime = system['wait_maxtime']

    def get_pid(self):
        return os.getpid()

    def get_lock(self):
        lockf = open(self.lock_file,'r')
        return lockf.read()

    def lock(self):
        pid = self.get_pid()
        lockf = open(self.lock_file,'w')
        lockf.write(str(pid))
        lockf.close()

    def unlock(self):
        if os.path.isfile(self.lock_file):
            os.remove(self.lock_file)

    def check(self):
        count = 1
        countmax = int(self.wait_maxtime)/int(self.wait_time)
        while os.path.isfile(self.lock_file):
            if count <= countmax:
                break
            lock_pid = self.get_lock()
            cmd = "ps aux|grep %s | grep FNSynchro.py | wc -l" %lock_pid
            running_pids = commands.getoutput(cmd) 
            if int(running_pids) != 1:
                log.info("removing stale lock file")
                break
            else:
                time.sleep()
                count = count + 1
        self.unlock()

#rsyn wrapper
def rsync(src,dst,filters=[]):
    """ 
    Wrapoper around rsync program
    accepts
        str(src): rsync source
        str(dst): rsync destination
        str(filters): a long string of filters to apply to the rsync cli (refer to the rsync man pages for --filter and "FILTER RULES")
    returns
        Bool
    """
    count = 0
    cmd = "rsync -rLpt --delete --delete-after --inplace %s %s %s" % (filters, src, dst)
    log.info(cmd)
    status = -1
    while status not in [None, 0] and count < 3:
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            log.error(output)
            count = count+1
        else:
            return True
    return False

#generate the filters
def filter_gen(npattern,ipath=[],filter=''):
    """
    Takes a pattern as defined in the cfg file and creates a set of "--filter=" arguments to be passed to the rsyn command later
    accepts
        npattern: a list of lists of the path defined
        e.g. [['fremantle', 'harmattan'], ['pool', 'dists'], ['default'], ['current', 'pre-release', 'previous']]
        str(filter): a filter to be added to the filters generated, when passed it preceeds the filters generated by this function
    returns
        str(filters): a string of "--filter=" arguments
    """
    if len(npattern) < 1:
        return filter
    if len(ipath) == 0:
        ipath = ['']
    sub_list = npattern.pop(0)
    tmp_ipath = []
    for old_path in ipath:
        for item in sub_list:
            path = os.path.join(old_path,item)
            filter = filter + "--filter='+ %s' "%path
            tmp_ipath.append(path)
    for dir in tmp_ipath:
        filter = filter + "--filter='- %s/*' " %os.path.dirname(dir)
    return filter_gen(npattern,tmp_ipath,filter)

def sync(config):
    npattern = config['pattern']
    filters = filter_gen(npattern)
    if config['excludes']:
        for exclude in config['excludes']:
            filters = filters + "--exclude='%s' " %exclude
    if len(config['exceptions']) > 0:
        for exception in config['exceptions']:
            filters = filters + "--filter='+ **%s' " % exception
        filters = filters + "--filter='+ **%s' " % os.path.dirname(exception)
    return rsync(config['src'],config['dst'],filters)

class htaccess:

    def __init__(self, config, depthfirst = True, hidden = False, dir_only = True):
        self.depthfirst = depthfirst
        self.hidden = hidden
        self.dir_only = dir_only
        self.product = config['product'][0]
        ## only works on nekta
        #from optparse import OptionParser
        #os.environ['DJANGO_SETTINGS_MODULE'] = 'pdbv2db.settings'
        #from pdbv2db.db.models import Source
        #from pdbv2db.db.models import Copyright
        #colist = Copyright.objects.filter(source__component__project__product__name=product).distinct()
        #self.CO = []
        #for co in colist:
        #    if str(co) !=  'Unknown' or str(co).startswith('*'):
        #        self.CO.append(str(co))
        #end
        self.CO = ['nokia-closed', 'modified', 'ossw', 'nokia-open', 'zi', 'hanwang', 'art', 'ti', 'customization', 'real', 'nokia-emc', 'adobe','nokia-maps', 'eff', 'skype']
        self.pattern = config['pattern']
        self.config = config

    def trees_gen(self, npattern, ipath=[], trees=[]):
        if len(npattern) < 1:
            return trees
        if len(ipath) == 0:
            ipath = ['']
        sub_list = npattern.pop(0)
        tmp_ipath = []
        for old_path in ipath:
            for item in sub_list:
                path = os.path.join(old_path,item)
                trees.append(path)
                tmp_ipath.append(path)
        return self.trees_gen(npattern,tmp_ipath,trees)

    def __walktree (self, top, depthfirst = True):
        names = os.listdir(top)
        if not depthfirst:
            yield top, names
        for name in names:
            try:
                if not self.hidden and name.startswith('.'):
                    continue
                st = os.lstat(os.path.join(top, name))
            except os.error:
                continue
            if stat.S_ISDIR(st.st_mode):
                if not self.dir_only:
                    yield top, names
                for (newtop, children) in self.__walktree (os.path.join(top, name), depthfirst):
                    yield newtop, children
        if depthfirst:
            yield top, names

#    def walktree(self):
#        for top in self.pattern[0]:
#            for lower in self.pattern[1]:
#                log.debug(os.path.join(self.config['src'],top,lower))
#                top = os.path.join(self.config['src'],top,lower)
#                return self.__walktree(top, self.depthfirst)

        

    def create_htaccess(self, path, product, type, CO = None):
        ldapserver = 'localhost'
        base = """AuthType                    basic
        AuthName                    "OSSO External Repository"
        AuthBasicProvider           ldap
        AuthLDAPGroupAttribute      memberUid
        AuthLDAPGroupAttributeIsDN  off
        AuthLDAPURL             ldap://%s/dc=osso?uid?sub?(employeeType=active)
        """ %ldapserver
        #generate group attributes 
        #type:[binary,source,images], CO:copyright-owner
        group = "cn=repo"
        if type:
            group = group + "_%s" %type
        if type != "images" and CO:
            group = group + "_%s" %CO
        require = "require ldap-group " + group + ",ou=%s," %product + "ou=products,ou=groups,dc=osso"
        #htaccess_file = open(os.path.join(path,type,'.htaccess'), 'w')
        #htaccess_file.write(base)
        #htaccess_file.write(require)
        #htaccess_file.close()
        print "create htaccess in: " + os.path.join(path,type,'.htaccess')
        print require


    def doit(self):
        pat = re.compile(r'(binary|source).*')
        trees = self.trees_gen(self.pattern)
        for tree in trees:
            path = os.path.join(self.config['src'], tree)
            children = os.listdir(path)
            for child in children:
                curdir = os.path.join(path, child)
                if child in self.CO:
                    log.debug('child is a CO')
                    for child_sub in os.listdir(curdir):
                        _path = None
                        if child_sub.startswith('binary'):
                            type = 'binary'
                            _path = os.path.join(curdir,type)
                        elif child_sub.startswith('source'):
                            type = 'source'
                            _path = os.path.join(curdir,type)
                        if _path and os.path.exists(_path):
                            H.create_htaccess(curdir, self.product, type, child)
                if os.path.isdir(curdir):
                    if self.config.has_key('htaccess_dir'):
                        if child in self.config['htaccess_dir'][0]:
                            H.create_htaccess(curdir, self.product, "images")
        return True

#main
cfg = initConfig()
configs = cfg.get_config()
l = lock(system)
l.check()
l.lock()
for config in configs.keys():
    if config not in ['general', 'system']: 
        log.debug('%s = %s' %(config,configs[config]))
        log.info("start writig htaccess files")
        H = htaccess(configs[config])
        if not H.doit():
            log.error('create htaccess failed')
        else:
            log.info("done")
        log.info("start rsync")
        if not sync(configs[config]):
            log.error('rsync failed')
        else:
            log.info("done")
l.unlock
