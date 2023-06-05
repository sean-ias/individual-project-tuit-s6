def is_valid_card(card_number):
    total_sum = 0
    length = len(card_number)
    alternate = False

    for i in range(length - 1, -1, -1):
        digit = int(card_number[i])
        if alternate:
            digit *= 2
            if digit > 9:
                digit -= 9
        alternate = not alternate
        total_sum += digit

    return total_sum % 10 == 0


def is_supported_card(card_number):
    if len(card_number) == 13 and card_number[0] == '4':
        return True  # Visa
    if len(card_number) == 16:
        if card_number[0] == '4':
            return True  # Visa
        if "51" <= card_number[:2] <= "55":
            return True  # Mastercard
        if card_number[:4] == "9860":
            return True  # Humo
        if card_number[:4] == "8600":
            return True  # Uzcard
    if len(card_number) == 15 and (card_number[:2] == "34" or card_number[:2] == "37"):
        return True  # American Express

    return False


def main():
    card_number = input("Enter the credit card number: ")

    if is_supported_card(card_number) and is_valid_card(card_number):
        print("The card number is valid. ", end="")
        if card_number[0] == '3':
            print("The card type is American Express.")
        elif card_number[0] == '4':
            print("The card type is VISA.")
        elif card_number[0] == '5':
            print("The card type is Mastercard.")
        elif card_number[0] == '8':
            print("The card type is Uzcard.")
        else:
            print("The card type is Humo.")
    else:
        print("The card number is invalid or not supported.")


if __name__ == "__main__":
    main()