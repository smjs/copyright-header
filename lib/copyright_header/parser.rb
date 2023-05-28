#
# Copyright Header - A utility to manipulate copyright headers on source code files
# Copyright (C) 2012-2016 Erik Osterman <e@osterman.com>
#
# This file is part of Copyright Header.
#
# Copyright Header is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Copyright Header is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Copyright Header.  If not, see <http://www.gnu.org/licenses/>.
#
require 'fileutils'
require 'yaml'
require 'erb'
require 'ostruct'
require 'linguist'
require 'set'
require 'pathname'

module Boolean; end
class TrueClass; include Boolean; end
class FalseClass; include Boolean; end

module CopyrightHeader
  class FileNotFoundException < Exception; end
  class ExistingLicenseException < Exception; end
  class FileOptException < Exception; end

  class License
    @lines = []
    def initialize(options)
      @options = options
      @lines = load_template.split(/\n/).map { |line| line += "\n" }
    end

    def word_wrap(text, max_width = nil)
      max_width ||= @options[:word_wrap]
      text.gsub(/(.{1,#{max_width}})(\s|\Z)/, "\\1\n")
    end

    def load_template
      if File.exists?(@options[:license_file])
        template = ::ERB.new File.new(@options[:license_file]).read, 0, '%'
        license = template.result(OpenStruct.new(@options).instance_eval { binding })
        license = word_wrap(license)
        license
      else
        raise FileNotFoundException.new("Unable to open #{file}")
      end
    end

    def format(comment_open = nil, comment_close = nil, comment_prefix = nil)
      comment_open ||= ''
      comment_close ||= ''
      comment_prefix ||= ''
      license = comment_open + @lines.map { |line| (comment_prefix + line).gsub(/\s+\n$/, "\n") }.join() + comment_close
      license.gsub!(/\\n/, "\n")
      license
    end
  end

  class Header
    @file = nil
    @contents = nil
    @config = nil

    def initialize(file, config)
      @file = file
      @contents = File.read(@file)
      @config = config
    end

    def format(license)
      license.format(@config[:comment]['open'], @config[:comment]['close'], @config[:comment]['prefix'])
    end

    def add(license, check_regex = nil)
      if has_copyright?(check_regex)
        raise ExistingLicenseException.new("detected existing license")
      end

      copyright = self.format(license)
      if copyright.nil?
        STDERR.puts "Copyright is nil"
        return nil
      end

      text = ""
      if @config.has_key?(:after) && @config[:after].instance_of?(Array)
        copyright_written = false
        lines = @contents.split(/\n/, -1)
        head = lines.shift(10)
        while(head.size > 0)
          line = head.shift
          text += line + "\n"
          @config[:after].each do |regex|
            pattern = Regexp.new(regex)
            if pattern.match(line)
              text += copyright
              copyright_written = true
              break
            end
          end
        end
        if copyright_written
          text += lines.join("\n")
        else
          text = copyright + text + lines.join("\n")
        end
      else
        # Simply prepend text
        text = copyright + @contents
      end
      return text
    end

    def remove(license, check_regex = nil)
      if has_copyright?(check_regex)
        text = self.format(license)
        # Due to editors messing with whitespace, we'll make this more of a fuzzy match and use \s to match whitespace
        pattern = Regexp.escape(text).gsub(/\\[ n]/, '\s*').gsub(/\\s*$/, '\s')
        exp = Regexp.new(pattern)
        @contents.gsub!(exp, '')
        @contents
      else
        STDERR.puts "SKIP #{@file}; copyright not detected"
        return nil
      end
    end

    def has_copyright?(regex_str = nil, lines = 10)
      regex_str ||= '(?!class\s+)([Cc]opyright|[Ll]icense)\s'
      exp = Regexp.new(regex_str)
      @contents.split(/\n/)[0..lines].select { |line| exp.match(line) }.length > 0
    end
  end

  class Syntax
    attr_accessor :guess_extension

    def initialize(config, guess_extension = false)
      @guess_extension = guess_extension
      @config = {}
      syntax = YAML.load_file(config)
      syntax.each_value do |format|
        format['ext'].each do |ext|
          @config[ext] = {
            :before => format['before'],
            :after => format['after'],
            :comment => format['comment']
          }
        end
      end
    end

    def ext(file)
      extension = File.extname(file)
      if @guess_extension && (extension.nil? || extension.empty?)
        extension = Linguist::FileBlob.new(file).language.extensions.first
      end
      return extension
    end

    def supported?(file, type)
      extension = (type != nil ? type : ext(file))
      @config.has_key?(extension)
    end

    def header(file, type)
      extension = (type != nil ? type : ext(file))
      Header.new(file, @config[extension])
    end
  end

  class Configuration
    @@valid_file_keys = Set[ :syntax, :ext, :include, :license_file, :license, :word_wrap,
                             :copyright_software, :copyright_software_description,
                             :copyright_years, :copyright_holders, :check_regex ]

    @@file_opt_type_sets = {}
    @@file_opt_type_sets[::Boolean] = Set[ :include ]
    @@file_opt_type_sets[::Integer] = Set[ :word_wrap ]
    @@file_opt_type_sets[::Array] = Set[ :copyright_years, :copyright_holders ]
    @@file_opt_type_sets[::String] = @@valid_file_keys -
          (@@file_opt_type_sets[::Boolean] | @@file_opt_type_sets[::Integer] | @@file_opt_type_sets[::Array])
    @@file_opt_files = [ :syntax, :license_file ]

    def initialize(dir, options = {})
      @options = options
      @default_license = License.new(:license_file => @options[:license_file],
                                     :copyright_software => @options[:copyright_software],
                                     :copyright_software_description => @options[:copyright_software_description],
                                     :copyright_years => @options[:copyright_years],
                                     :copyright_holders => @options[:copyright_holders],
                                     :word_wrap => @options[:word_wrap])
      @default_syntax = Syntax.new(@options[:syntax], @options[:guess_extension])

      @dir = dir
      @matched_key_cache = {}

      @conf = {}
      if File.file?("#{dir}/.cr_conf.yml")
        STDERR.puts "GOT a .cr_conf.yml for dir #{dir}"
        @conf = read_conf("#{dir}/.cr_conf.yml")
      end
    end

    def has_custom_options?(base_name)
      return (get_key(base_name) != nil)
    end

    def get_key(base_name)
      if ! @matched_key_cache.key?(base_name)
        # Prioritise exact key match over glob match
        if @conf.key?(base_name)
          @matched_key_cache[base_name] = base_name
        else
          @conf.each_key do | key |
            if File.fnmatch(key, base_name)
              if @matched_key_cache.key?(base_name)
                STDERR.puts "WARNING: File #{base_name} matches multiple keys in .cr_conf.yml in @dir"
              else
                @matched_key_cache[base_name] = key
              end
            end
          end
        end
        @matched_key_cache[base_name] = nil if ! @matched_key_cache.key?(base_name)
      end

      return @matched_key_cache[base_name]
    end

    def options_for_file(base_name)
      file_opts = @options
      matched_key = get_key(base_name)

      if matched_key != nil
        file_opts = @conf[matched_key]
      end
      return file_opts
    end

    def license_for_file(base_name)
      license = @default_license

      if has_custom_options?(base_name)
        file_opts = options_for_file(base_name)
        if file_opts[:license_file] != @options[:license_file] ||
           @options[:copyright_software] != file_opts[:copyright_software] ||
           @options[:copyright_software_description] != file_opts[:copyright_software_description] ||
           @options[:copyright_years] != file_opts[:copyright_years] ||
           @options[:copyright_holders] != file_opts[:copyright_holders] ||
           @options[:word_wrap] != file_opts[:word_wrap]

          STDERR.puts "USING custom license for #{base_name}"
          license = License.new(:license_file => file_opts[:license_file],
                                :copyright_software => file_opts[:copyright_software],
                                :copyright_software_description => file_opts[:copyright_software_description],
                                :copyright_years => file_opts[:copyright_years],
                                :copyright_holders => file_opts[:copyright_holders],
                                :word_wrap => file_opts[:word_wrap])
        end
      end
      return license
    end

    def syntax_for_file(base_name)
      syntax = @default_syntax

      if has_custom_options?(base_name)
        file_opts = options_for_file(base_name)
        if file_opts[:syntax] != @options[:syntax]
          STDERR.puts "USING custom syntax for #{base_name}"
          syntax = Syntax.new(file_opts[:syntax], file_opts[:guess_extension])
        end
      end
      return syntax
    end

    def expand_env(str)
      str.gsub(/\$([a-zA-Z_][a-zA-Z0-9_]*)|\${\g<1>}|%\g<1>%/) { ENV[$1] }
    end

    def check_file_conf(conf_filename, file, file_opts)
      begin
        opt_keys = file_opts.keys.to_set

        if !opt_keys.subset?(@@valid_file_keys)
          raise FileOptException.new("have #{opt_keys.inspect} valid #{@@valid_file_keys.inspect}")
        end

        if opt_keys.include?(:license_file) && opt_keys.include?(:license)
          raise FileOptException.new("have both :license and :license_file options")
        end

        @@file_opt_type_sets.each do |type, key_set|
          check_file_opt_type(file_opts, opt_keys & key_set, type);
        end

        if opt_keys.include?(:include) && file_opts[:include] == false && opt_keys.size() > 1
          STDERR.puts "WARNING: In #{conf_filename} for #{file} - ':include' set to false, but other options provided"
        end

      rescue FileOptException => e
        STDERR.puts "ERROR: invalid file_opt keys in #{conf_filename} for #{file} - #{e.message}"
        exit(1);
      end
    end

    def check_file_opt_type(file_opts, key_set, type)
      key_set.each do |opt_key|
        if !file_opts[opt_key].is_a?(type)
          raise FileOptException.new("type wrong for '#{opt_key}', expect #{type}")
        end
      end
    end

    def read_conf(conf_filename)
      conf = File.open(conf_filename, 'r:bom|utf-8') { |f|
        YAML.safe_load f, [], [], false, conf_filename, symbolize_names: true
      }

      if conf == nil
        conf = []
        STDERR.puts "NOTE: #{conf_filename} is empty"
      end

      config = {}
      conf.each do |file, file_opts|
        check_file_conf(conf_filename, file, file_opts)

        if file_opts.has_key?(:license)
          file_opts[:license_file] = @options[:base_path] + '/licenses/' + file_opts[:license] + '.erb'
        end

        @@file_opt_files.each do |file_key|
          file_opts[file_key] = expand_env(file_opts[file_key]) if file_opts.has_key?(file_key)
        end

        full_file_opts = @options.merge(file_opts)

        begin
          @@file_opt_files.each do |file_key|
            unless File.file?(full_file_opts[file_key])
              raise FileOptException.new("Invalid #{file_key} value. Cannot open #{full_file_opts[file_key]}")
            end
          end
        rescue FileOptException => e
          STDERR.puts "ERROR: In #{conf_filename} for #{file} - #{e.message}"
          exit(1);
        end

        begin
          if file_opts.has_key?(:license)
            raise FileOptException.new("Missing copyright-software:") if full_file_opts[:copyright_software].nil?
            raise FileOptException.new("Missing copyright-software-description:") if full_file_opts[:copyright_software_description].nil?
            raise FileOptException.new("Missing copyright-holder:") unless full_file_opts[:copyright_holders].length > 0
            raise FileOptException.new("Missing copyright-year:") unless full_file_opts[:copyright_years].length > 0
          end
        rescue FileOptException => e
          STDERR.puts "ERROR: In #{conf_filename} for #{file} - #{e.message} (required when using :license)"
          exit(1);
        end

        config[file.to_s] = full_file_opts
      end

      return config
    end
  end

  class Parser
    def initialize(options = {})
      @options = options
      @exclude = [ /^LICENSE(|\.txt)$/i, /^holders(|\.txt)$/i, /^README/, /^\./]
    end

    def execute
      if @options.has_key?(:add_path)
        @options[:add_path].split(File::PATH_SEPARATOR).each { |path| add(path) }
      end

      if @options.has_key?(:remove_path)
        @options[:remove_path].split(File::PATH_SEPARATOR).each { |path| remove(path) }
      end
    end

    def transform(method, path)
      paths = []
      prefixed_path_pn = (Pathname.new(@options[:prefix_dir]) + path).cleanpath

      if prefixed_path_pn.file?
        top_dir_pn = prefixed_path_pn.dirname
        paths << prefixed_path_pn.to_s
      elsif prefixed_path_pn.directory?
        top_dir_pn = prefixed_path_pn
        paths.push(*Dir.glob(top_dir_pn + "{*,.*}"))
      else
        STDERR.puts "ERROR: #{prefixed_path_pn} not found"
        exit(1);
      end

      process_paths(method, top_dir_pn.to_s, paths)
    end

    # Note: This is a recursive method
    def process_paths(method, dir, paths)
      configuration = Configuration.new(dir, @options)

      paths.each do |path|
        begin
          base_name = File.basename(path)
          file_opts = configuration.options_for_file(base_name)

          skip_reason = nil
          if configuration.has_custom_options?(base_name)
            skip_reason = "excluded in .cr_conf.yml" if file_opts[:include] == false
          else
            skip_reason = "excluded" if base_name.match(Regexp.union(@exclude))
          end

          if File.directory?(path)
            # check for . and .. - recursing on these is bad
            next if base_name == "." || base_name == ".."

            if skip_reason == nil 
              sub_paths = Dir.glob("#{path}/{*,.*}")
              process_paths(method, path, sub_paths)
            else
              skip_or_copy(path, skip_reason)
            end
            next
          elsif !File.file?(path)
            STDERR.puts "SKIP #{path}; not file"
            next
          elsif skip_reason != nil
            skip_or_copy(path, skip_reason)
            next
          end

          syntax = configuration.syntax_for_file(base_name)
          license = configuration.license_for_file(base_name)
          ext_override = file_opts.has_key?(:ext) ? file_opts[:ext] : nil
          check_regex = file_opts.has_key?(:check_regex) ? file_opts[:check_regex] : nil

          if syntax.supported?(path, ext_override)
            header = syntax.header(path, ext_override)
            contents = header.send(method, license, check_regex)
            if contents.nil?
              skip_or_copy(path, "failed to #{method == "add:" ? "add" : "remove"} license")
            else
              write(path, contents)
            end
          else
            skip_or_copy(path, "unsupported #{ext_override == nil ? syntax.ext(path) : ext_override}")
          end
        rescue Exception => e
          STDERR.puts "SKIP #{path}; exception=#{e.message}"
        end
      end
    end

    # Add copyright header recursively
    def add(dir)
      transform(:add, dir)
    end

    # Remove copyright header recursively
    def remove(dir)
      transform(:remove, dir)
    end

    def output_dir_for_file(file)
      cleaned_path = Pathname.new(file).dirname.cleanpath
      dir = Pathname.new("#{@options[:output_dir]}/#{cleaned_path.sub(@options[:prefix_dir],'')}").cleanpath.to_s
    end

    def write(file, contents)
      if @options[:dry_run]
        STDERR.puts "UPDATE #{file} [dry-run]"
        STDERR.puts contents
      elsif @options[:output_dir].nil?
        STDERR.puts "UPDATE #{file} [no output-dir]"
        STDERR.puts contents
      else
        dir = output_dir_for_file(file)

        STDERR.puts "UPDATE #{file} [output-dir #{dir}]"

        FileUtils.mkpath dir unless File.directory?(dir)

        output_path = dir + "/" + File.basename(file)
        f =File.new(output_path, 'w')
        f.write(contents)
        f.close
      end
    end

    def skip_or_copy(file, reason)
      if ! @options[:write_all]
        STDERR.puts "SKIP #{file}; #{reason}"
      else
        if @options[:output_dir].nil?
          STDERR.puts "COPY #{file} [no output-dir] (will SKIP if output dir == input dir)"
        else
          dir = output_dir_for_file(file)
          input_dir = Pathname.new(file).dirname.cleanpath.to_s

          if dir == input_dir
            STDERR.puts "SKIP #{file}; won't COPY - input and output paths identical"
          else
            STDERR.puts "COPY #{file} [output-dir #{dir}] (skip reason was: #{reason})"

            if !@options[:dry_run]
              FileUtils.mkpath dir unless File.directory?(dir)
              FileUtils.cp_r(file, dir, :preserve => true)
            end
          end
        end
      end
    end

  end
end
