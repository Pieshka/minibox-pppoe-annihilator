// @license magnet:?xt=urn:btih:d3d9a9a6595521f9666a5e94cc830dab83b65699&dn=expat.txt Expat

/////////////////////////
//                     //
// Minibox i18n Script //
//                     //
/////////////////////////

/*  Main locale setting variable
    Defaults to en
*/
let mnbox_i18n_locale = 'en';

/* Try to load user prefered */
if(navigator.language.includes('en'))
	mnbox_i18n_locale = 'en';
else if(navigator.language.includes('pl'))
	mnbox_i18n_locale = 'pl';


/*  Now the translation data 
    Currently only two languages:
    pl, en
*/

let mnbox_i18n_messages = {
    pl: {
        basic: {
            appliance_name: 'Minibox',
            appliance_full_name: 'Minibox PPPoE Annihilator',
            loading_text: 'Ładowanie, proszę czekać...',
            rebooting_text: 'Ponowne uruchamianie...',
            connection_error: 'Błąd połączenia',
            saving_changes_text: 'Zapisywanie zmian...',
            saving_changes_session_expired: 'Sesja wygasła! Zmiany nie zostały zapisane.',
            saving_changes_rebooting: 'Zmiany zapisane, trwa ponowne uruchamianie...',
            saving_changes_done: 'Ponowne uruchomienie urządzenia zakończone pomyślnie!',
            saving_changes_timeout: 'Zmiany zapisane, ale urządzenie nie odpowiadało przez dłuższą chwilę. Prawdopodobnie zmienił się adres IP.',
            saving_changes_error: 'Wystąpił błąd podczas zapisywania zmian!',
            save_changes: 'Zapisz zmiany i uruchom ponownie',
            save_changes_noreboot: 'Zapisz zmiany',
            save_changes_tooltip: 'Nie zapomnij zapisać zmian przed opuszczeniem strony!',

            footer_text: `Minibox PPPoE Annihilator dostępny jest na licencji MIT. Więcej informacji w zakładce "Pomoc".`
        },

        login_dialog: {
            title: 'Logowanie',
            provide_password: 'Aby kontynuować należy podać poprawne hasło dostępowe.',
            password: 'Hasło',
            login_button: 'Zaloguj',

            password_empty: 'Podane hasło nie może być puste',
            invalid_password: 'Podane hasło jest nieprawidłowe',
            login_error: 'Błąd logowania'
        },

        menu_bar: {
            status: 'Status urządzenia',
            status_tooltip: 'Przegląd stanu interfejsów, usług i adresacji',
            wan: 'Interfejs WAN',
            wan_tooltip: 'Konfiguracja interfejsu WAN i protokołu PPPoE',
            lan: 'Interfejs LAN',
            lan_tooltip: 'Konfiguracja interfejsu LAN i serwera DHCP',
            security: 'Zabezpieczenia',
            security_tooltip: 'Konfiguracja zabezpieczeń systemu',
            device: 'Zasilanie urządzenia',
            device_tooltip: 'Ponowne uruchomienie, bądź wyłączenie urządzenia',
            help: 'Pomoc',
            help_tooltip: 'Pomoc, dokumentacja i informacje o licencjach',
            logout: 'Wyloguj',
            logout_tooltip: 'Wylogowanie z panelu'
        },

        status_page: {
            title: 'Status urządzenia',
            interfaces: 'Interfejsy',
            interface: 'Interfejs',
            if_name: 'Systemowe oznaczenie',
            state: 'Stan',
            wan: 'WAN',
            vlan: 'VLAN (ID: {id}, PRI: {pcp})',
            pppoe: 'PPPoE',
            lan: 'LAN',

            internal_services: 'Usługi wewnętrzne',
            service: 'Usługa',
            dhcp_server: 'Serwer DHCP',
            ppp_client: 'Klient PPPoE',
            http_server: 'Serwer HTTP',

            device_addresses: 'Adresacja urządzenia',
            address_type: 'Rodzaj adresu',
            ip_address: 'Adres IP',
            ppp_address: 'Adres przydzielony przez PPPoE',
            gw_address: 'Adres bramy przydzielony przez PPPoE',
            lan_address: 'Adres interfejsu LAN',
            dns1_address: 'Adres DNS 1',
            dns2_address: 'Adres DNS 2',

            active: 'Aktywny',
            inactive: 'Nieaktywny',
            connecting: 'Łączenie...',
            not_configured: 'Nieskonfigurowany',

            help_interfaces: 'Pomoc - Interfejsy',
            help_interfaces_text: 'Sekcja <em><b>Interfejsy</b></em> zawiera informacje o stanie interfejsów fizycznych oraz logicznych dostępnych w systemie.',
            help_interfaces_states: 'Możliwe stany i ich znaczenie:',
            help_interfaces_active: '<span class="mnbox-color-good">Aktywny</span> - interfejs działa poprawnie i jest gotowy do przesyłania ruchu',
            help_interfaces_notconfigured: '<span class="mnbox-color-neutral">Nieskonfigurowany</span> - interfejs nie został skonfigurowany do poprawnej pracy',
            help_interfaces_connecting: '<span class="mnbox-color-warning">Łączenie</span> - używany jedynie w przypadku PPPoE, sygnalizuje działanie klienta PPPoE lecz towarzyszący mu interfejs nie jest jeszcze aktywny',
            help_interfaces_inactive: '<span class="mnbox-color-fail">Nieaktywny</span> - interfejs nie jest aktywny, w przypadku interfejsów fizycznych najczęściej oznacza to odłączony kabel',

            help_services: 'Pomoc - Usługi wewnętrzne',
            help_services_text: 'Sekcja <em><b>Usługi wewnętrzne</b></em> zawiera informacje o stanie usług działających w systemie. '+
            'Stan usług może być <span class="mnbox-color-good">Aktywny</span>, <span class="mnbox-color-fail">Nieaktywny</span>, bądź <span class="mnbox-color-neutral">Nieskonfigurowany</span>,'+
            ' gdy usługa nie została skonfigurowana przez użytkownika.',

            help_addresses: 'Pomoc - Adresacja urządzenia',
            help_addresses_text: 'Sekcja <em><b>Adresacja urządzenia</b></em> zawiera informacje o adresacji przydzielonej przez serwer PPPoE operatora.'+
            ' Pole <i>Adres bramy przydzielony przez PPPoE</i> jest pokazywane tylko gdy używana jest maska 32-bitowa po stronie LAN.'
        },

        wan_page: {
            title: 'Konfiguracja interfejsu WAN',
            ethernet_settings: 'Ustawienia protokołu Ethernet',
            enable_vlan: 'Włącz obsługę VLAN typu 802.1q',
            vlan_id: 'Identyfikator sieci VLAN',
            vlan_pcp: 'Priorytet sieci VLAN (PCP)',
            according_isp: 'Skonfiguruj parametry sieci VLAN zgodnie z zaleceniami operatora',
            pppoe_mac: 'Alternatywny adres MAC interfejsu WAN',

            pppoe_settings: 'Ustawienia protokołu PPPoE',
            pppoe_user: 'Nazwa użytkownika',
            pppoe_password: 'Hasło dostępowe',
            hidden: 'Ukryte',
            pppoe_service: 'Nazwa usługi (Service Name)',
            pppoe_mtu: 'Rozmiar MTU dla interfejsu PPPoE',

            help_ethernet: 'Pomoc - Ustawienia Ethernet',
            help_ethernet_text1: 'Sekcja <em><b>Ustawienia protokołu Ethernet</b></em> umożliwia skonfigurowanie fizycznego interfejsu WAN.',
            help_ethernet_text2: 'Operatorzy najczęściej dostarczają usługi współdzielone: Internet, Telewizja oraz Telefon za pomocą dedykowanych sieci wirtualnych typu 802.1q.'+
                        'Należy wówczas zaznaczyć opcję <em>Włącz obsługę VLAN typu 802.1q</em> i wpisanie prawidłowego identyfikatora sieci VLAN. W niektórych '+
                        'przypadkach konieczne również będzie ustawienie poprawnego priorytetu (PCP) sieci VLAN. Należy się skonsultować się z operatorem w celu uzyskania '+
                        'tych informacji. Klienci biznesowi niekiedy mają terminowane sieci VLAN na urządzeniach operatora - obsługa sieci VLAN powinna wtedy pozostać wyłączona.',
            help_ethernet_text3: 'Jeżeli istnieje potrzeba, można również skonfigurować inny adres MAC na interfejsie WAN, aczkolwiek zalecane jest aby pozostać przy domyślnym adresie '+
                        'karty sieciowej, a spróbować skontaktować się z operatorem w celu autoryzacji innego adresu MAC.',
            
            help_pppoe: 'Pomoc - Ustawienia PPPoE',
            help_pppoe_text1: 'Sekcja <em><b>Ustawienia protokołu PPPoE</b></em> umożliwia skonfigurowanie logicznego interfejsu klienta PPPoE.',
            help_pppoe_text2: 'Najważniejszymi parametrami koniecznymi do działania usługi są <em>Nazwa użytkownika</em> oraz <em>Hasło</em>. '+
                        'Opcjonalnie można również podać wpisać nazwę usługi - jeżeli operator tego wymaga. Należy przy tym być świadomy, '+
                        'że podanie nazwy usługi wymusza na kliencie PPPoE akceptację ofert jedynie od serwerów z taką nazwą, zatem jeżeli '+
                        'nie ma potrzeby podania nazwy usługi to należy pozostawić te pole puste.',
            help_pppoe_text3: 'Konfiguracja rozmiaru ramki (parametr MTU) jest konieczna jedynie w przypadku posiadania łącz Internetowych '+
                        'o zwiększonej przepustowości (najczęściej 1 Gigabit oraz więcej). Wtedy zalecaną wartością jest <b>1500</b>. '+
                        'Dla ofert o niższych parametrach zupełnie wystarczy domyślna wartość MTU <b>1492</b>. Dokładnie taką wartość '+
                        'należy też ustawić, gdyby operator nie obsługiwał ramek o zwiększonym rozmiarze.'

        },

        lan_page: {
            title: 'Konfiguracja interfejsu LAN',
            ip_settings: 'Ustawienia adresacji IP',
            lan_mask: 'Maska podsieci interfejsu LAN',
            pick_mask: 'Wybierz maskę podsieci',
            single_host: 'Pojedynczy host PPPoE /32',
            point_point_net: 'Sieć typu punkt-punkt /31',
            standard_net_30: 'Standardowa sieć /30',
            standard_net_24: 'Standardowa sieć /24',
            lan_ip: 'Adres IP interfejsu LAN',
            enter_ip: 'Podaj adres IP urządzenia jaki ma zostać ustawiony na interfejsie LAN',

            dhcp_settings: 'Ustawienia serwera DHCP',
            lan_dhcp: 'Włącz wbudowany serwer DHCP',
            lan_lease: 'Czas trwania dzierżawy (s)',
            lan_lease_info: 'Aby ustawić nieskończony czas dzierżawy, należy wpisać wartość 0',

            additional_settings: 'Dodatkowe funkcjonalności',
            mangle_ttl: 'Włącz nadpisywanie pola TTL',
            mangle_ttl_info: 'Nadpisywanie pola TTL ukrywa obecność Miniboxa w wynikach narzędzi typu traceroute',

            help_addresses: 'Pomoc - Ustawienia adresacji IP',
            help_addresses_text1: 'Sekcja <em><b>Ustawienia adresacji IP</b></em> pozwala określić sposób udostępniania adresu IP otrzymanego z sesji PPPoE na interfejsie LAN.',
            help_addresses_masks: 'Możliwe maski podsieci i konsekwencje ich wyboru:',
            help_addresses_single: '<b>Pojedynczy host PPPoE /32</b> - LAN działa jako interfejs punkt-punkt. Adres lokalny ustawiany jest poprzez pole '+
                                '<i>Adres IP interfejsu LAN</i>, zdalny (routera docelowego) pochodzi od serwera PPPoE. DHCP (jeśli aktywny) ' +
                                'przydziela adres /32 i bramę z PPPoE.',
            help_addresses_point: '<b>Sieć typu punkt-punkt /31</b> - adres LAN wyliczany jest na podstawie adresu PPPoE z maską /31. Następuje '+
                                'utrata dostępu do sąsiedniego adresu IP w Internecie (traktowany jest jako lokalny). DHCP przydziela adres /31 i bramę '+
                                'lokalną.',
            help_addresses_std30: '<b>Standardowa sieć /30</b> - interfejs LAN uzyskuje podsieć /30 na podstawie adresu IP z PPPoE. Następuje utrata '+
                                'dostępu do 3 publicznych IP z tej przestrzeni (traktowane są jako lokalne). DHCP działa analogicznie jak w poprzednim trybie.',
            help_addresses_std24: '<b>Standardowa sieć /24</b> - interfejs LAN uzyskuje podsieć /24 na podstawie adresu IP z PPPoE. Następuje utrata '+
                                'dostępu do 255 adresów z tej przestrzeni (traktowane są jako lokalne). DHCP działa analogicznie jak w poprzednim trybie.',
            help_addresses_text2: 'Więcej informacji na temat działania tych ustawień znajduje się w sekcji <b>Pomoc</b>.',

            help_dhcp: 'Pomoc - Ustawienia serwera DHCP',
            help_dhcp_text1: 'Sekcja <em><b>Ustawienia serwera DHCP</b></em> umożliwia skonfigurowanie wbudowanego serwera DHCP.',
            help_dhcp_text2: 'Wbudowany serwer DHCP służy do automatycznego przydzielania adresu IP urządzeniu podpiętemu do interfejsu LAN. '+
                        'Szczególnie jest przydatny, gdy przydzielany przez operatora adres jest adresem dynamicznym, ulegającym zmianie co '+
                        'jakiś czas. Jeżeli adres IP jest statyczny i znany, to można bezpiecznie wyłączyć serwer DHCP. '+
                        'Czas trwania dzierżawy powinien być najkrótszy, jeżeli posiadamy dynamiczny adres IP.'
        },

        security_page: {
            title: 'Zabezpieczenia',
            change_password: 'Zmiana hasła dostępowego',
            new_password: 'Nowe hasło',
            repeat_new_password: 'Powtórz nowe hasło',

            password_not_match: 'Podane hasła się nie zgadzają',
            password_set_error: 'Wystąpił błąd podczas ustawiania nowego hasła',
            password_set_success: 'Pomyślnie zmieniono hasło dostępowe',

            help_info: 'Ważna informacja',
            help_text1: 'Hasło dostępowe do panelu webowego Miniboxa, jest zarazem hasłem do powłoki systemowej. Należy mieć to na uwadze, jeżeli '+
                        'Minibox jest również konfigurowany bezpośrednio z systemu operacyjnego. Po zmianie hasła najlepiej jest zapisać go w bezpiecznym '+
                        'miejscu, np. w menedżerze haseł.'
        },

        device_page: {
            title: 'Zasilanie urządzenia',
            reboot_title: 'Ponowne uruchomienie',
            reboot_text: 'Ponowne uruchomienie spowoduje całkowite przeładowanie systemu operacyjnego, jego usług i konfiguracji.',
            reboot: 'Uruchom ponownie',

            reboot_dialog: 'Trwa ponowne uruchamianie...',

            shutdown_title: 'Wyłączenie',
            shutdown_text: 'Zalecanym sposobem wyłączenia urządzenia jest użycie poniższego przycisku, bądź też wyłączenie z poziomu powłoki systemowej.',
            shutdown: 'Wyłącz urządzenie',

            shutdown_dialog: 'Urządzenie wyłączy się za chwilę. Możesz bezpiecznie opuścić tę stronę.'
        },

        help_page: {
            title: 'Pomoc',
            about_system: 'O systemie',
            warning_system: 'UWAGA! System na którym obecnie pracujesz wykonany został jako proof of concept i nie został przetestowany w środowiskach korporacyjnych! '+
                        'Autor nie gwarantuje jego długoterminowego działania. Przed instalacją na produkcji należy dokładnie przebadać jego stabilność. Niezalecane jest '+
                        'korzystanie z rodzajów obrazów do celów innych niż testowe i laboratoryjne. Zalecane jest zbudowanie dedykowanego jądra ze sterownikami pod dane '+
                        'urządzenie.',
            about_paragraph1: '<b>Minibox PPPoE Annihilator</b> to dedykowany system operacyjny oparty na kernelu Linux, którego przeznaczeniem jest terminacja sesji PPPoE przed docelowym '+
                    'routerem w sieci lokalnej. Bardzo często specjalistyczne routery typu NGFW, IDS/IPS, bądź systemy routerowego ogólnego przeznaczenia mają bardzo kiepską obsługę '+
                    'PPPoE lub nie mają jej wcale.',
            about_paragraph2: 'Celem projektu jest oddelegowanie konieczności obsługi sesji PPPoE na dedykowane urządzenie, w taki sposób, aby dla urządzeń znajdujących '+
                    'się zarówno u operatora jak i u abonenta, pozostało ono niewidoczne. Minibox to <b>NIE</b> jest router, firewall, ani inne urządzenie, które ma stanowić rdzeń całej sieci '+
                    'lokalne. Udostępnianie panelu konfiguracyjnego zarówno po stronie LAN jak i po stronie WAN jest <b>wysoce</b> niewskazane.',
            about_paragraph3: 'Minibox sam w sobie nie posiada dostępu do sieci Internet, co odróżnia go mocno od pozostałych rozwiązań dostępnych w routerach innych producentów takich jak '+
                    '<i>IP Passthrough</i> czy <i>True IP DMZ</i>. Nie wymaga również dedykowanej podsieci udostępnianej przez operatora i działa z klasycznymi jednoadresowymi usługami '+
                    'konsumenckimi (nie jest również zatem prostym <i>Half-Bridge</i>).',
            
            how_works: 'Zasada działania',
            how_works_paragraph1: 'Działanie Miniboxa bardzo podobne jest do klasycznego przełącznika z tą różnicą, że całość odbywa się na warstwie trzeciej modelu OSI. Kiedy klient PPPoE nawiąże sesję '+
                    'z serwerem, Minibox zdejmuje adres IP z interfejsu PPP i przekazuje go na interfejs LAN. Sposób tego przekazania jest konfigurowalny przez użytkownika. Protokół PPP tworzy sieć '+
                    'typu punkt-punkt, jednak jest znacznie starszy niż standard RFC3021, który wprowadził sieci punkt-punkt (maskę /31) do adresacji IPv4. Z tego powodu wiele klientów PPPoE zakłada maskę /32, '+
                    'ponieważ ta najbardziej oddaje charakterystykę tego kanału komunikacji. Poza tym brama operatora często ma zupełnie inny adres IP, niż wynikało by to z maski /31.',
            how_works_paragraph2: 'Niestety dużo urządzeń i systemów operacyjnych nie obsługuje maski /32 na zwykłym interfejsie Ethernet. Te znane z obsługi tego typu sieci to <i>Microsoft Windows</i>, obecne wersje <i>Linux</i> '+
                    'oraz <i>MikroTik RouterOS</i>. Dla tego typu urządzeń przygotowany został tryb <b>Pojedynczy host PPPoE</b>, w którym Minibox ustawia sobie dowolnie wybrany adres IP, a adresem peera (naszego routera) '+
                    'jest adres przydzielony przez serwer PPPoE. Ustawia również proxy ARP dla adresu bramy naszego operatora aby łapać zapytania ARP, które nasze urządzenie będzie wysyłało na interfejs lokalny. Nie powoduje '+
                    'to jednak, że prawdziwa brama operatora zostanie przejęta przez Miniboxa. Pingi wysyłane na adres bramy operatora, dalej będą trafiać do niej trafiać. Jedynie adres który wybierzemy "przepadnie", dlatego '+
                    'domyślnie jest to adres z puli laboratoryjnej (203.0.113.0/24). Jest to najlepszy tryb ze wszystkich, ponieważ nie tracimy dostępu do żadnych innych adresów IP.',
            how_works_paragraph3: 'Jeżeli nasze urządzenie nie obsługuje maski /32 albo nie akceptuje faktu, że brama jest w innej podsieci jak adres IP, ale wspiera standard RFC3021 (maska /31) to możemy skorzystać z trybu <b>Sieć typu punkt-punkt</b>. '+
                    'W tym trybie Minibox całkowicie zignoruje informacje o bramie udostępnianej przez operatora (nie będzie w ogóle wykorzystywana). Zamiast wybranego adresu IP, na interfejsie LAN ustawiony zostaje '+
                    'adres z podsieci /31. Dla przykładu, jeżeli nasz operator udostępnia nam adres IP 192.168.1.1, to Minibox przydzieli sobie adres 192.168.1.0/31. Serwer DHCP nie będzie już rozdawał bramy operatora, '+
                    'ponieważ ta najczęściej znajduje się w osobnej podsieci, ale jako bramę będzie podawał bezpośrednio adres Miniboxa (w naszym przykładzie jest to 192.168.1.0). Brama zatem znajduje się w tej samej podsieci '+
                    'co adres hosta, aczkolwiek w przypadku RFC3021 i maski /31, nie ma koncepcji adresu sieci i adresu rozgłoszeniowego. Powoduje to więc, że tracimy dostęp tylko do jednego adresu IP - jeżeli dla przykładu '+
                    'nasz sąsiad dostał od operatora 192.168.1.0 to teraz ten adres jest traktowany jako lokalny Miniboxowi i nie będzie wypuszczany do Internetu. Na szczęście bardzo rzadko potrzebujemy łączyć się z adresami sąsiednich '+
                    'do naszych.',
            how_works_paragraph4: 'Najgorszym scenariuszem jest brak obsługi zarówno maski /32, jak i standardu RFC3021 i maski /31. Wtedy jesteśmy zmuszeni skorzystać z trybu <b>Standardowa sieć /30</b> lub <b>Standardowa sieć /24</b>. '+
                    'W tych trybach Minibox traktuje adres IP otrzymany przez operatora jako cześć lokalnej sieci o masce /30 lub masce /24. Są to najbardziej kompatybilne tryby, gdyż w taki sposób działają obecne sieci. '+
                    'Czasem operatorzy oferują stałe adresy IP z maską /30, z tylko jednym efektywnym adresem (jeden przeznaczony jest dla routera operatora, a dwa pozostałe to adresy sieci i rozgłoszeniowy). Dokładnie w taki '+
                    'sposób działa też Minibox. Przydziela sobie najbliższy wolny adres IP, a ten, który operator przydzielił przesyła urządzeniowi końcowemu. Przy masce /30 tracimy jedynie 3 adresy z sieci Internet, które '+
                    'traktowane są odtąd za lokalne, a przy masce /24 tracimy ich aż 255.',
            how_works_paragraph5: 'Oprócz tego, Minibox oferuje również pewną funkcję o nazwie <b>nadpisywanie TTL</b>. Powoduje ona zwiększenia wartości TTL w pakietach IP o 1, przez co narzędzia typu traceroute czy tracepath nie mogą '+
                    'wykryć Miniboxa po drodze - z perspektywy użytkownika końcowego Minibox jest zupełnie przezroczysty. Oczywiście, jeżeli taka opcja modyfikacji pakietów nie jest akceptowalna to można ją wyłączyć, jednak '+
                    'wtedy traceroute i podobne narzędzia będą pokazywać po drodze adres IP Miniboxa.',
            
            licensing: 'Licencjonowanie',
            licensing_paragraph: 'Wszystkie skrypty, pliki WWW, aplikacja CGI webapi oraz inne elementy mojego autorstwa wchodzące w skład Minibox PPPoE Annihilator są dostępne na licencji MIT. '+
                    'Praw autorskich do logotypu oraz nazwy "Minibox PPPoE Annihilator" sobie nie roszczę i pozwalam budować własne implementacje. Aczkolwiek jeżeli stworzysz coś lepszego, '+
                    'to raczej lepiej będzie, żeby nie było to utożsamiane z gorszym oryginałem. W przypadku pozostałych komponentów działanie mają ich poszczególne licencje.',
            licensing_external: 'Minibox PPPoE Annihilator, korzysta z następujących narzędzi dostępnych na osobnych licencjach:',
            licensing_external_others: 'A także inne narzędzia udostępiane za pomocą pakietu Buildroot'
        }
    },

    en: {
        basic: {
            appliance_name: 'Minibox',
            appliance_full_name: 'Minibox PPPoE Annihilator',
            loading_text: 'Loading, please wait...',
            rebooting_text: 'Rebooting...',
            connection_error: 'Connection error',
            saving_changes_text: 'Saving changes...',
            saving_changes_session_expired: 'Session expired! Changes have not been saved.',
            saving_changes_rebooting: 'Changes saved, rebooting...',
            saving_changes_done: 'The device has been successfully rebooted!',
            saving_changes_timeout: 'The changes were saved, but the device did not respond for a long time. The IP address has probably changed.',
            saving_changes_error: 'An error occurred while saving changes!',
            save_changes: 'Save changes and reboot.',
            save_changes_noreboot: 'Save changes',
            save_changes_tooltip: 'Don\'t forget to save your changes before leaving the page!',

            footer_text: `The Minibox PPPoE Annihilator is available under the MIT licence. For more information, see the 'Help' tab.`
        },

        login_dialog: {
            title: 'Log in',
            provide_password: 'To continue, please enter the correct access password.',
            password: 'Password',
            login_button: 'Login',

            password_empty: 'The password you entered cannot be empty.',
            invalid_password: 'The password you entered is incorrect.',
            login_error: 'Login error'
        },

        menu_bar: {
            status: 'Device status',
            status_tooltip: 'Overview of the status of interfaces, services and addressing',
            wan: 'WAN interface',
            wan_tooltip: 'WAN interface and PPPoE protocol configuration',
            lan: 'LAN interface',
            lan_tooltip: 'LAN interface and DHCP server configuration',
            security: 'Security',
            security_tooltip: 'System security configuration',
            device: 'Power',
            device_tooltip: 'Rebooting or shutting down the device',
            help: 'Help',
            help_tooltip: 'Help, documentation, and licence information',
            logout: 'Log out',
            logout_tooltip: 'Logging out of the panel'
        },

        status_page: {
            title: 'Device status',
            interfaces: 'Interfaces',
            interface: 'Interface',
            if_name: 'Kernel interface name',
            state: 'State',
            wan: 'WAN',
            vlan: 'VLAN (ID: {id}, PRI: {pcp})',
            pppoe: 'PPPoE',
            lan: 'LAN',

            internal_services: 'Internal services',
            service: 'Service',
            dhcp_server: 'DHCP server',
            ppp_client: 'PPPoE client',
            http_server: 'HTTP server',

            device_addresses: 'IP addressing',
            address_type: 'Address type',
            ip_address: 'IP address',
            ppp_address: 'Address assigned by PPPoE',
            gw_address: 'Gateway address assigned by PPPoE',
            lan_address: 'LAN interface address',
            dns1_address: 'DNS address 1',
            dns2_address: 'DNS address 2',

            active: 'Active',
            inactive: 'Inactive',
            connecting: 'Connecting...',
            not_configured: 'Not configured',

            help_interfaces: 'Help - Interfaces',
            help_interfaces_text: 'The <em><b>Interfaces</b></em> section contains information about the status of physical and logical interfaces available in the system.',
            help_interfaces_states: 'Possible states and their meanings:',
            help_interfaces_active: '<span class="mnbox-color-good">Active</span> - the interface is functioning properly and is ready to transmit traffic.',
            help_interfaces_notconfigured: '<span class="mnbox-color-neutral">Not configured</span> - the interface has not been configured to work properly.',
            help_interfaces_connecting: '<span class="mnbox-color-warning">Connecting</span> - used only in the case of PPPoE, it signals the operation of the PPPoE client, but the accompanying interface is not yet active.',
            help_interfaces_inactive: '<span class="mnbox-color-fail">Inactive</span> - the interface is not active. In the case of physical interfaces, this usually means that the cable is disconnected.',

            help_services: 'Help - Internal services',
            help_services_text: 'The <em><b>Internal services</b></em> contains information about the status of services operating in the system. '+
            'The status of a service can be <span class="mnbox-color-good">Active</span>, <span class="mnbox-color-fail">Inactive</span>, or <span class="mnbox-color-neutral">Not configured</span>'+
            ' when the service has not been configured by the user',

            help_addresses: 'Help - IP addressing',
            help_addresses_text: 'The <em><b>IP addressing</b></em> contains information about the address assigned by the ISP\'s PPPoE server.'+
            ' The <i>Gateway address assigned by PPPoE</i> field is only displayed when a 32-bit mask is used on the LAN side.'
        },

        wan_page: {
            title: 'WAN interface configuration',
            ethernet_settings: 'Ethernet protocol settings',
            enable_vlan: 'Enable 802.1q VLAN support',
            vlan_id: 'VLAN identifier',
            vlan_pcp: 'VLAN priority (PCP)',
            according_isp: 'Configure the VLAN parameters according to the ISP\'s recommendations.',
            pppoe_mac: 'Alternative MAC address of the WAN interface',

            pppoe_settings: 'PPPoE protocol settings',
            pppoe_user: 'Username',
            pppoe_password: 'Password',
            hidden: 'Hidden',
            pppoe_service: 'Service Name',
            pppoe_mtu: 'MTU size for PPPoE interface',

            help_ethernet: 'Help - Ethernet Settings',
            help_ethernet_text1: 'The <em><b>Ethernet Protocol Settings</b></em> section allows you to configure the physical WAN interface.',
            help_ethernet_text2: 'ISPs most often provide shared services: Internet, TV and telephone using dedicated 802.1q virtual networks.'+
                        'In this case, select the <em>Enable 802.1q VLAN support</em> option and enter the correct VLAN ID. In some '+
                        'cases, it will also be necessary to set the correct VLAN priority (PCP). Consult your ISP for '+
                        'this information. Business customers sometimes have terminated VLANs on the operator\'s devices - VLAN support should then remain disabled.',
            help_ethernet_text3: 'If necessary, you can also configure a different MAC address on the WAN interface, although it is recommended to stick with the default address of the network card and contact your operator to authorise a different MAC address.',
            
            help_pppoe: 'Help - PPPoE settings',
            help_pppoe_text1: 'The <em><b>PPPoE Protocol Settings</b></em> section allows you to configure the PPPoE client logical interface.',
            help_pppoe_text2: 'The most important parameters necessary for the service to work are the <em>Username</em> and <em>Password</em>. Optionally, you can also enter the service name, if required by the ISP. Please note that entering the service name forces the PPPoE client to accept offers only from servers with that name, so if there is no need to enter the service name, leave this field blank.',
            help_pppoe_text3: 'Configuring the frame size (MTU parameter) is only necessary if you have Internet connections with increased bandwidth (usually 1 Gigabit or more). In such cases, the recommended value is <b>1500</b>. For connections with lower parameters, the default MTU value of <b>1492</b> is sufficient. This is also the value that should be set if the operator does not support larger frames.'

        },

        lan_page: {
            title: 'LAN interface configuration',
            ip_settings: 'IP address settings',
            lan_mask: 'LAN interface subnet mask',
            pick_mask: 'Select subnet mask',
            single_host: 'Single /32 PPPoE host',
            point_point_net: 'Point-to-point /31 network',
            standard_net_30: 'Standard /30 network',
            standard_net_24: 'Standard /24 network',
            lan_ip: 'LAN interface IP address',
            enter_ip: 'Enter the IP address of the device to be set on the LAN interface.',

            dhcp_settings: 'DHCP server settings',
            lan_dhcp: 'Enable the built-in DHCP server',
            lan_lease: 'Lease duration (s)',
            lan_lease_info: 'To set an infinite lease time, enter the value 0.',

            additional_settings: 'Additional features',
            mangle_ttl: 'Enable TTL mangle',
            mangle_ttl_info: 'Mangling the TTL field hides the presence of Minibox in the results of traceroute-type tools.',

            help_addresses: 'Help - IP address settings',
            help_addresses_text1: 'The <em><b>IP address</b></em> settings section allows you to specify how to share the IP address obtained from the PPPoE session on the LAN interface.',
            help_addresses_masks: 'Possible subnet masks and the consequences of their selection:',
            help_addresses_single: '<b>Single /32 PPPoE host</b> - the LAN operates as a point-to-point interface. The local address is set via the <i>LAN interface IP address</i> field, while the remote address (of the destination router) is obtained from the PPPoE server. DHCP (if enabled) assigns a /32 address and gateway from PPPoE.',
            help_addresses_point: '<b>Point-to-point /31 network</b> - the LAN address is calculated based on the PPPoE address with a /31 mask. Access to the neighbouring IP address on the Internet is lost (it is treated as local). DHCP assigns a /31 address and a local gateway.',
            help_addresses_std30: '<b>Standard /30 network</b> - the LAN interface obtains a /30 subnet based on the IP address from PPPoE. Access to 3 public IPs from this space is lost (they are treated as local). DHCP works in the same way as in the previous mode.',
            help_addresses_std24: '<b>Standard /24 network</b> - the LAN interface obtains a /24 subnet based on the IP address from PPPoE. Access to 255 addresses from this space is lost (they are treated as local). DHCP works in the same way as in the previous mode.',
            help_addresses_text2: 'For more information on how these settings work, see the <b>Help</b> section.',

            help_dhcp: 'Help - DHCP server settings',
            help_dhcp_text1: 'The <em><b>DHCP server settings</b></em> section allows you to configure the built-in DHCP server.',
            help_dhcp_text2: 'The built-in DHCP server is used to automatically assign an IP address to a device connected to the LAN interface. It is particularly useful when the address assigned by the operator is a dynamic address that changes from time to time. If the IP address is static and known, the DHCP server can be safely disabled. The lease duration should be as short as possible if you have a dynamic IP address.'
        },

        security_page: {
            title: 'Security',
            change_password: 'Changing your access password',
            new_password: 'New password',
            repeat_new_password: 'Repeat your new password',

            password_not_match: 'The passwords you entered do not match',
            password_set_error: 'An error occurred while setting a new password',
            password_set_success: 'Password successfully changed',

            help_info: 'Important information',
            help_text1: 'The access password for the Minibox web panel is also the password for the system shell. This should be kept in mind if the Minibox is also configured directly from the operating system. After changing the password, it is best to save it in a secure place, e.g. in a password manager.'
        },

        device_page: {
            title: 'Power',
            reboot_title: 'Reboot this device',
            reboot_text: 'Rebooting will completely reload the operating system, its services, and configuration.',
            reboot: 'Reboot',

            reboot_dialog: 'Rebooting...',

            shutdown_title: 'Shutdown this device',
            shutdown_text: 'The recommended way to turn off the device is to use the button below or to turn it off from the system shell.',
            shutdown: 'Shutdown',

            shutdown_dialog: 'The device will shut down shortly. You can safely leave this page.'
        },

        help_page: {
            title: 'Help',
            about_system: 'About the system',
            warning_system: 'WARNING! The system you are currently working on was created as a proof of concept and has not been tested in corporate environments! '+
                        'The author does not guarantee its long-term operation. Before installing it in production, its stability should be thoroughly tested. It is not recommended to '+
                        'use generic images for purposes other than testing and laboratory use. It is recommended to build a dedicated kernel with drivers for the specific '+
                        'device.',
            about_paragraph1: '<b>Minibox PPPoE Annihilator</b> is a dedicated operating system based on the Linux kernel, designed to terminate PPPoE sessions before the target '+
                    'router in the local network. Very often, specialised routers such as NGFW, IDS/IPS, or general-purpose router systems have very poor support for '+
                    'PPPoE support or none at all.',
            about_paragraph2: 'The aim of the project is to delegate the need to handle PPPoE sessions to a dedicated device in such a way that it remains invisible to devices located '+
                    'both at the operator\'s and the subscriber\'s premises. The minibox is <b>NOT</b> a router, firewall or other device that is intended to be the core of the entire local network. '+
                    'Sharing the configuration panel on both the LAN and WAN sides is <b>highly</b> inadvisable.',
            about_paragraph3: 'The Minibox itself does not have access to the Internet, which distinguishes it significantly from other solutions available in routers from other manufacturers, '+
                    'such as <i>IP Passthrough</i> or <i>True IP DMZ</i>. It also does not require a dedicated subnet provided by the operator and works with classic single-address consumer services (it is therefore '+
                    'not a simple <i>Half-Bridge</i> either).',
            
            how_works: 'How it',
            how_works_paragraph1: 'The operation of Minibox is very similar to that of a classic switch, with the difference that everything takes place on the third layer of the OSI model. When a PPPoE client establishes '+
                     'a session with the server, Minibox removes the IP address from the PPP interface and transfers it to the LAN interface. The method of transfer is configurable by the user. The PPP protocol creates a point-to-point '+
                    'network, but it is much older than the RFC3021 standard, which introduced point-to-point networks (/31 mask) to IPv4 addressing. For this reason, many PPPoE clients assume a /32 mask, as this best reflects the characteristics '+
                    'of this communication channel. In addition, the operator\'s gateway often has a completely different IP address than would be expected from the /31 mask.',
            how_works_paragraph2: 'Unfortunately, many devices and operating systems do not support the /32 mask on a standard Ethernet interface. Those known to support this type of network include <i>Microsoft Windows</i>, current versions of <i>Linux</i>, and '+
                    '<i>MikroTik RouterOS</i>. For this type of device, a <b>Single /32 PPPoE host</b> mode has been prepared, in which Minibox sets itself any IP address, and the peer address (our router) is the address assigned by the PPPoE server. It also sets up a proxy ARP '+
                    'for our operator\'s gateway address to catch ARP queries that our device will send to the local interface. However, this does not cause the operator\'s real gateway to be taken over by Minibox. Pings sent to the operator\'s gateway address will '+
                    'continue to reach it. Only the address we select will be "lost", which is why the default address is from the laboratory pool (203.0.113.0/24). This is the best mode of all, as we do not lose access to any other IP addresses.',
            how_works_paragraph3: 'If our device does not support the /32 mask or does not accept the fact that the gateway is in a different subnet than the IP address, but supports the RFC3021 standard (/31 mask), we can use the <b>Point-to-point /31 network</b> mode. '+
                    'In this mode, Minibox will completely ignore the gateway information provided by the operator (it will not be used at all). Instead of the selected IP address, the LAN interface will be set to '+
                    'address from the /31 subnet is set on the LAN interface. For example, if our operator provides us with the IP address 192.168.1.1, the Minibox will assign itself the address 192.168.1.0/31. The DHCP server will no longer distribute the operator\'s gateway, '+
                    'because it is usually located in a separate subnet, but will directly provide the Minibox address as the gateway (in our example, this is 192.168.1.0). The gateway is therefore located in the same subnet '+
                    'as the host address, although in the case of RFC3021 and the /31 mask, there is no concept of a network address and a broadcast address. This means that we only lose access to one IP address - if, for example, '+
                    'our neighbour received 192.168.1.0 from the operator, this address is now treated as local to the Minibox and will not be released to the Internet. Fortunately, we very rarely need to connect to addresses neighbouring ours.',
            how_works_paragraph4: 'The worst-case scenario is when neither the /32 mask nor the RFC3021 standard and the /31 mask are supported. In this case, we are forced to use the <b>Standard /30 Network</b> or <b>Standard /24 Network</b> mode. '+
                    'In these modes, Minibox treats the IP address received from the operator as part of a local network with a /30 or /24 mask. These are the most compatible modes, as this is how current networks operate. Sometimes operators offer fixed IP '+
                    'addresses with a /30 mask, with only one effective address (one is reserved for the operator\'s router, and the other two are network and broadcast addresses). This is exactly how Minibox works. It assigns itself the nearest available IP '+
                    'address and forwards the one assigned by the operator to the end device. With a /30 mask, we only lose 3 addresses from the Internet network, which are now treated as local, and with a /24 mask, we lose as many as 255.',
            how_works_paragraph5: 'In addition, Minibox also offers a feature called <b>TTL mangling</b>. This increases the TTL value in IP packets by 1, preventing tools such as traceroute or tracepath from '+
                    'detect Minibox along the way - from the end user\'s perspective, Minibox is completely transparent. Of course, if this packet modification option is not acceptable, it can be disabled, but '+
                    'then traceroute and similar tools will show the Minibox IP address along the way.',
            
            licensing: 'Licensing',
            licensing_paragraph: 'All scripts, WWW files, the CGI webapi application, and other elements of my authorship included in Minibox PPPoE Annihilator are available under the MIT licence. '+
                    'I do not claim copyright to the logo and name "Minibox PPPoE Annihilator" and allow you to build your own implementations. However, if you create something better, '+
                    'it would be better not to associate it with the inferior original. In the case of other components, their individual licences apply.',
            licensing_external: 'The Minibox PPPoE Annihilator uses the following tools, available under separate licences:',
            licensing_external_others: 'As well as other tools provided by the Buildroot package'
        }
    }
}

/* Load languages into Alpine.js */
document.addEventListener('alpine-i18n:ready', () =>{
    window.AlpineI18n.create(mnbox_i18n_locale, mnbox_i18n_messages);
    window.AlpineI18n.fallbackLocale = 'en';
    /* Set document lang */
    document.documentElement.lang = window.AlpineI18n.locale;
});

// @license-end