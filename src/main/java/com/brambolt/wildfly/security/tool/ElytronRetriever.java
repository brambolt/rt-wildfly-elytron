/*
 * Copyright 2020 Brambolt ehf.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.brambolt.wildfly.security.tool;

import com.brambolt.wildfly.security.credential.store.CredentialStores;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.tool.ElytronToolMessages;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Companion to the <code>ElytronTool</code> - allows retrieving secrets.
 */
public class ElytronRetriever {

    /**
     * Main method. Prints the requested secret to standard out.
     *
     * @param args Command line parameters
     */
    public static void main(String[] args) {
        Options options = createOptions();
        Parameters parameters;
        try {
            parameters = Parameters.parse(args, options);
        } catch (IllegalArgumentException | ParseException x) {
            help(new Parameters(1 > args.length ? "" : args[0]), options);
            throw new RuntimeException("Unable to parse command line arguments", x);
        } catch (FileNotFoundException x) {
            help(new Parameters(1 > args.length ? "" : args[0]), options);
            throw new RuntimeException("Credential store not found", x);
        }
        try {
            if (parameters.help) {
                help(parameters, options);
                System.exit(0);
            }
            Security.addProvider(new WildFlyElytronProvider());
            CredentialStore store = CredentialStores.create(
                parameters.inputFile, parameters.password, false);
            char[] secret = CredentialStores.retrieveClearPassword(store, parameters.alias);
            if (null == secret)
                throw new IllegalStateException("No secret found for alias");
            System.out.print(secret);
            System.exit(0);
        } catch (CredentialStoreException x) {
            help(parameters, options);
            throw new RuntimeException("Unable to access credential store", x);
        } catch (IllegalStateException x) {
            help(parameters, options);
            throw new RuntimeException("No secret found for requested alias", x);
        } catch (NoSuchAlgorithmException x) {
            help(parameters, options);
            throw new RuntimeException("Internal error", x);
        }
        System.exit(-1);
    }

    public static void help(Parameters parameters, Options options) {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(1024);
        help.printHelp(
            String.format("%s %s", parameters.script, Parameters.CREDENTIAL_STORE_COMMAND),
            "Retrieves a clear text password for an alias",
            options,
            "",
            true);

    }

    public static class Parameters {

        public static final String CREDENTIAL_STORE_COMMAND = "credential-store";

        public final String script;

        public final String command;

        public final File inputFile;

        public final String password;

        public final String alias;

        public final Boolean help;

        public Parameters(String script, String command, File inputFile, String password, String alias) {
            this.script = script;
            this.command = command;
            this.inputFile = inputFile;
            this.password = password;
            this.alias = alias;
            this.help = false;
        }

        public Parameters(String script) {
            this.script = script;
            this.command = null;
            this.inputFile = null;
            this.password = null;
            this.alias = null;
            this.help = true;
        }

        static Parameters parse(String[] args, Options options)
            throws ParseException, FileNotFoundException {
            if (2 > args.length)
                throw new IllegalArgumentException("No parameters provided");
            String script = args[0];
            String command = args[1];
            if (!CREDENTIAL_STORE_COMMAND.equals(command))
                throw new IllegalArgumentException("Unknown command: " + command);
            CommandLine commandLine = new DefaultParser().parse(options, args, false);
            if (commandLine.hasOption(HELP_PARAM))
                return new Parameters(script);
            return new Parameters(
                script, command,
                parseInputFile(commandLine),
                parseStorePassword(commandLine),
                parseAlias(commandLine));
        }

        static File parseInputFile(CommandLine commandLine) throws FileNotFoundException {
            String path = commandLine.getOptionValue(STORE_LOCATION_PARAM);
            if (null == path || path.trim().isEmpty())
                throw new IllegalArgumentException("No input file provided");
            File file = new File(path);
            if (!file.exists())
                throw new FileNotFoundException("Not found: " + file.getAbsolutePath());
            return file;
        }

        static String parseStorePassword(CommandLine commandLine) {
            String value = commandLine.getOptionValue(CREDENTIAL_STORE_PASSWORD_PARAM);
            if (null == value || value.trim().isEmpty())
                throw new IllegalArgumentException("No store password provided");
            return value;
        }

        static String parseAlias(CommandLine commandLine) {
            String value = commandLine.getOptionValue(GET_SECRET_PARAM);
            if (null == value || value.trim().isEmpty())
                throw new IllegalArgumentException("No alias provided");
            return value;
        }
    }

    public static final String CREDENTIAL_STORE_PASSWORD_PARAM = "password";

    public static final String GET_SECRET_PARAM = "retrieve";

    public static final String HELP_PARAM = "help";

    public static final String STORE_LOCATION_PARAM = "location";

    static Options createOptions() {
        Options options = new Options();
        options.addOption(createLocationOption());
        options.addOption(createPasswordOption());
        options.addOptionGroup(createAliasOptionGroup());
        options.addOption(createHelpOption());
        return options;
    }

    static Option createLocationOption() {
        Option option = new Option("l", STORE_LOCATION_PARAM, true,
            ElytronToolMessages.msg.cmdLineStoreLocationDesc());
        option.setArgName("loc");
        option.setOptionalArg(false);
        return option;
    }

    static Option createPasswordOption() {
        Option option = new Option("p", CREDENTIAL_STORE_PASSWORD_PARAM, true,
            ElytronToolMessages.msg.cmdLineCredentialStorePassword());
        option.setArgName("pwd");
        return option;
    }

    static OptionGroup createAliasOptionGroup() {
        Option option = new Option("g", GET_SECRET_PARAM, true,
            "Retrieve secret for alias");
        option.setArgName("alias");
        OptionGroup group = new OptionGroup();
        group.addOption(option);
        return group;
    }

    static Option createHelpOption() {
        return new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
    }
}
